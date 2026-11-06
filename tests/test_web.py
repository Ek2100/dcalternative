from datetime import timedelta
from types import SimpleNamespace

import mongomock

from bot.service import utcnow
from core import crypto
from core.netcheck import empty_net, load_ranges
from web.app import create_app

PRIV, PUB = crypto.generate_job_keypair()
CF = {"CF-Connecting-IP": "203.0.113.7"}
LOOP = {"REMOTE_ADDR": "127.0.0.1"}


class FakeVpn:
    def __init__(self, vpn=False):
        self.vpn, self.seen = vpn, []

    def check(self, ip):
        self.seen.append(ip)
        return {**empty_net(True), "vpn": self.vpn}


def setup(turnstile_ok=True, vpn=False):
    db = mongomock.MongoClient(tz_aware=True)["t"]
    settings = SimpleNamespace(turnstile_site_key="site", turnstile_secret="sec", turnstile_hostname="h",
                               job_public_key=PUB, proxy_mode="tunnel")
    calls = []

    def turnstile(secret, response, ip, *, cdata, hostname):
        calls.append((response, ip, cdata))
        return turnstile_ok

    fake_vpn = FakeVpn(vpn)
    app = create_app(settings, db=db, vpn=fake_vpn, turnstile=turnstile, ranges=load_ranges())
    token, sid = crypto.new_session_token()
    db["verify_sessions"].insert_one({"_id": sid, "guild_id": 1, "status": "new",
                                      "expires_at": utcnow() + timedelta(minutes=10)})
    return app.test_client(), db, token, sid, calls, fake_vpn


def submit(client, token, **kw):
    return client.post(f"/v/{token}/submit", json={"turnstile": "tok", "signals": {"tz": "UTC"}},
                       headers=CF, environ_base=LOOP, **kw)


def test_page_renders_with_security_headers():
    client, *_ , token, sid, calls, _ = setup()
    r = client.get(f"/v/{token}", headers=CF, environ_base=LOOP)
    assert r.status_code == 200
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "Set-Cookie" not in r.headers
    assert sid[:32].encode() in r.data


def test_requests_not_from_cloudflare_are_refused():
    client, _, token, *_ = setup()
    r = client.post(f"/v/{token}/submit", json={}, headers=CF, environ_base={"REMOTE_ADDR": "198.51.100.4"})
    assert r.status_code == 403


def test_submit_seals_job_uses_cloudflare_ip_and_is_single_use():
    client, db, token, sid, calls, vpn = setup()
    r = submit(client, token)
    assert r.status_code == 202
    assert calls[0][1] == "203.0.113.7" and vpn.seen == ["203.0.113.7"]  # IP from Cloudflare's header
    job = db["verify_jobs"].find_one({})
    assert "203.0.113.7" not in repr(job)                 # IP never stored
    payload = crypto.open_job(PRIV, job["sealed"])
    assert payload["signals"]["tz"] == "UTC" and "203.0.113.7" not in repr(payload)
    assert submit(client, token).status_code == 410       # can't reuse the link
    assert client.get(f"/v/{token}/status").json["status"] == "submitted"


def test_failed_captcha_does_not_consume_link():
    client, db, token, *_ = setup(turnstile_ok=False)
    assert submit(client, token).status_code == 403
    assert db["verify_jobs"].count_documents({}) == 0
    assert db["verify_sessions"].find_one({})["status"] == "new"


def test_tor_flag_from_cloudflare():
    client, db, token, *_ = setup()
    client.post(f"/v/{token}/submit", json={"turnstile": "t", "signals": {}},
                headers={**CF, "CF-IPCountry": "T1"}, environ_base=LOOP)
    payload = crypto.open_job(PRIV, db["verify_jobs"].find_one({})["sealed"])
    assert payload["net"]["tor"] is True


def test_expired_and_bad_tokens():
    client, db, token, sid, *_ = setup()
    db["verify_sessions"].update_one({"_id": sid}, {"$set": {"expires_at": utcnow() - timedelta(seconds=1)}})
    assert client.get(f"/v/{token}", headers=CF, environ_base=LOOP).status_code == 410
    assert client.get("/v/not-a-token", headers=CF, environ_base=LOOP).status_code == 410


def test_body_size_limit():
    client, _, token, *_ = setup()
    r = client.post(f"/v/{token}/submit", data="x" * 20000, content_type="application/json",
                    headers=CF, environ_base=LOOP)
    assert r.status_code == 413
