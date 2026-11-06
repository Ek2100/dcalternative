from datetime import datetime, timedelta, timezone

import pytest

from core import crypto, matching, netcheck, signals


# ── crypto ────────────────────────────────────────────────────────────────────

def keyring():
    return crypto.Keyring.parse(f"a1:{crypto.b64e(b'A' * 32)},b2:{crypto.b64e(b'B' * 32)}")


def test_wrap_roundtrip_and_bound_to_guild():
    kr = keyring()
    raw = crypto.new_guild_key()
    wrapped = kr.wrap(1, raw)
    assert kr.unwrap(1, wrapped) == raw
    with pytest.raises(crypto.CryptoError):
        kr.unwrap(2, wrapped)  # can't move a key to another server


def test_old_master_key_still_unwraps_and_flags_rewrap():
    old = crypto.Keyring.parse(f"b2:{crypto.b64e(b'B' * 32)}")
    wrapped = old.wrap(5, b"k" * 32)
    kr = keyring()
    assert kr.unwrap(5, wrapped) == b"k" * 32
    assert kr.needs_rewrap(wrapped)


def test_bad_master_keys_rejected():
    with pytest.raises(crypto.CryptoError):
        crypto.Keyring.parse("")
    with pytest.raises(crypto.CryptoError):
        crypto.Keyring.parse("a1:" + crypto.b64e(b"short"))


def test_guild_key_hashes_differ_between_servers():
    a = crypto.GuildKey(1, b"x" * 32)
    b = crypto.GuildKey(2, b"y" * 32)
    assert a.sig("canvas", "v") == crypto.GuildKey(1, b"x" * 32).sig("canvas", "v")
    assert a.sig("canvas", "v") != b.sig("canvas", "v")
    assert a.sig("canvas", "v") != a.sig("webgl", "v")
    assert a.uid_tag(42) != b.uid_tag(42)


def test_missing_signal_is_never_hashed():
    k = crypto.GuildKey(1, b"x" * 32)
    assert k.sig("canvas", "") is None and k.sig("canvas", None) is None


def test_uid_encryption_bound_to_guild():
    a = crypto.GuildKey(1, b"x" * 32)
    blob = a.seal_uid(123456789012345678)
    assert a.open_uid(blob) == 123456789012345678
    with pytest.raises(crypto.CryptoError):
        crypto.GuildKey(2, b"x" * 32).open_uid(blob)


def test_session_tokens():
    token, sid = crypto.new_session_token()
    assert crypto.valid_token_format(token)
    assert crypto.session_id(token) == sid and token not in sid
    assert not crypto.valid_token_format("../../etc")


def test_sealed_jobs():
    priv, pub = crypto.generate_job_keypair()
    blob = crypto.seal_job(pub, {"a": 1})
    assert crypto.open_job(priv, blob) == {"a": 1}
    other_priv, _ = crypto.generate_job_keypair()
    with pytest.raises(crypto.CryptoError):
        crypto.open_job(other_priv, blob)


# ── signals ───────────────────────────────────────────────────────────────────

def test_clean_signals_drops_bad_values():
    out = signals.clean_signals({
        "device": "A" * 43, "canvas": "f" * 64, "webgl": "<script>", "screen": "1920x1080x24@1.25",
        "tz": "America/Argentina/Buenos_Aires", "lang": "en-US,en", "evil": "x", "noisy": True,
        "hw": "8|8",
    })
    assert out["device"] == "A" * 43 and out["canvas"] == "f" * 64
    assert out["webgl"] is None and "evil" not in out and out["noisy"] is True
    assert out["screen"] and out["tz"] and out["hw"]
    assert signals.clean_signals("nope")["device"] is None


def test_ua_family():
    ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"
    assert signals.ua_family(ios) == "ios-safari" and signals.is_ios("ios-safari")
    win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0"
    assert signals.ua_family(win) == "windows-edge"
    assert signals.clean_uafam("windows-edge") == "windows-edge"
    assert signals.clean_uafam("bogus") is None


# ── matching ──────────────────────────────────────────────────────────────────

BASE = {"canvas": "c", "webgl": "w", "audio": "a", "fonts": "f", "screen": "s", "tz": "t", "lang": "l"}


def test_device_token_is_strong():
    assert matching.compare({"device": "d"}, {"device": "d"}).level == matching.STRONG


def test_all_traits_strong_three_medium_less_none():
    assert matching.compare(BASE, dict(BASE)).level == matching.STRONG
    assert matching.compare(BASE, {**BASE, "audio": "x"}).level == matching.MEDIUM
    assert matching.compare(BASE, {**BASE, "audio": "x", "fonts": "y"}).level == matching.NONE
    assert matching.compare(BASE, {**BASE, "tz": "other"}).level == matching.MEDIUM


def test_low_entropy_only_never_matches():
    low = {"screen": "s", "tz": "t", "lang": "l"}
    assert matching.compare(low, dict(low)).level == matching.NONE


def test_missing_values_never_match_each_other():
    assert matching.compare({"canvas": None}, {"canvas": None}).level == matching.NONE


def test_ios_downgrade_but_not_for_device_token():
    assert matching.compare(BASE, dict(BASE), ios=True).level == matching.MEDIUM
    assert matching.compare({**BASE, "audio": "x"}, BASE, ios=True).level == matching.NONE
    assert matching.compare({"device": "d"}, {"device": "d"}, ios=True).level == matching.STRONG


def test_decide():
    clean = {"vpn": False, "tor": False, "datacenter": False}
    vpn = {**clean, "vpn": True}
    strong = matching.Match(matching.STRONG)
    assert matching.decide(net=clean, vpn_policy="block", banned_matches=[]).action == "verify"
    assert matching.decide(net=vpn, vpn_policy="block", banned_matches=[]).action == "block"
    assert matching.decide(net=vpn, vpn_policy="review", banned_matches=[]).action == "review"
    assert matching.decide(net=vpn, vpn_policy="allow", banned_matches=[]).action == "verify"
    assert matching.decide(net=clean, vpn_policy="allow", banned_matches=[strong]).action == "review"


# ── client IP behind Cloudflare ───────────────────────────────────────────────

RANGES = netcheck.load_ranges()


def test_tunnel_mode_trusts_header_only_from_loopback():
    h = {"CF-Connecting-IP": "203.0.113.9"}
    assert netcheck.client_ip("127.0.0.1", h, "tunnel", RANGES) == "203.0.113.9"
    with pytest.raises(netcheck.UntrustedSource):
        netcheck.client_ip("198.51.100.1", h, "tunnel", RANGES)


def test_direct_mode_requires_cloudflare_peer():
    h = {"CF-Connecting-IP": "2001:db8::1"}
    assert netcheck.client_ip("172.68.1.1", h, "direct", RANGES) == "2001:db8::1"
    assert netcheck.client_ip("2606:4700::1", h, "direct", RANGES) == "2001:db8::1"
    with pytest.raises(netcheck.UntrustedSource):
        netcheck.client_ip("8.8.8.8", h, "direct", RANGES)


def test_spoofed_or_missing_header_rejected():
    with pytest.raises(netcheck.UntrustedSource):
        netcheck.client_ip("127.0.0.1", {"CF-Connecting-IP": "not-an-ip"}, "tunnel", RANGES)
    with pytest.raises(netcheck.UntrustedSource):
        netcheck.client_ip("127.0.0.1", {"X-Forwarded-For": "1.2.3.4"}, "tunnel", RANGES)


def test_tor_header():
    assert netcheck.cloudflare_says_tor({"CF-IPCountry": "T1"})
    assert not netcheck.cloudflare_says_tor({"CF-IPCountry": "AU"})


# ── Turnstile ─────────────────────────────────────────────────────────────────

class FakeHttp:
    def __init__(self, data=None, exc=None):
        self.data, self.exc, self.sent = data, exc, None

    def post(self, url, data, timeout):
        if self.exc:
            raise self.exc
        self.sent = data
        return type("R", (), {"json": lambda s: self.data})()


NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def good(**over):
    return {"success": True, "action": "verify", "cdata": "abc", "hostname": "verify.example.com",
            "challenge_ts": (NOW - timedelta(seconds=30)).isoformat().replace("+00:00", "Z"), **over}


def ts(data=None, exc=None):
    return netcheck.verify_turnstile("secret", "tok", "1.2.3.4", cdata="abc", hostname="verify.example.com",
                                     http=FakeHttp(data, exc), now=NOW)


def test_turnstile_checks():
    assert ts(good())
    assert not ts(good(success=False))
    assert not ts(good(action="login"))
    assert not ts(good(cdata="other"))
    assert not ts(good(hostname="evil.example"))
    assert not ts(good(challenge_ts=(NOW - timedelta(minutes=10)).isoformat()))
    assert not ts(exc=OSError("down"))
