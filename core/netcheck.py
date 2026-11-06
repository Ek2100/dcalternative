"""Network checks for the verification page: the real client IP behind
Cloudflare, VPN/proxy/datacenter detection, and Cloudflare Turnstile.

The visitor's IP address lives only in memory for the length of one request.
It is never logged, stored, or sent anywhere except Cloudflare (who already
has it, as our proxy) for the Turnstile check.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Iterable, Mapping, Optional

import requests

log = logging.getLogger(__name__)

# ── Client IP behind Cloudflare ───────────────────────────────────────────────

# Cloudflare's published edge ranges (https://www.cloudflare.com/ips/).
# They rarely change, but check them when you deploy, or point
# CLOUDFLARE_IPS_FILE at a file with one CIDR per line that you refresh.
CLOUDFLARE_RANGES = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

PROXY_MODES = ("tunnel", "direct", "insecure-dev")
_LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))


class UntrustedSource(Exception):
    """The request did not come through Cloudflare, so its headers can't be trusted."""


def load_ranges(path: Optional[str] = None) -> list:
    lines: Iterable[str] = CLOUDFLARE_RANGES
    if path:
        with open(path, encoding="utf-8") as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    nets = [ipaddress.ip_network(l, strict=False) for l in lines]
    if not nets:
        raise ValueError("no Cloudflare ranges loaded")
    return nets


def _in(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr.version == n.version and addr in n for n in nets)


def client_ip(remote_addr: Optional[str], headers: Mapping[str, str], mode: str, ranges) -> str:
    """Return the visitor's IP as Cloudflare reports it.

    * ``tunnel``: Cloudflare Tunnel (cloudflared) runs on this machine and is the
      only thing that can reach the app (we bind to 127.0.0.1). The connection
      must come from loopback; the IP is taken from ``CF-Connecting-IP``.
    * ``direct``: Cloudflare connects straight to us. The TCP peer must be one of
      Cloudflare's ranges, otherwise anyone could fake ``CF-Connecting-IP``.
    * ``insecure-dev``: local testing only; uses the TCP peer.

    ``X-Forwarded-For`` is never used: clients can set it to anything.
    """
    if mode == "insecure-dev":
        ip = remote_addr or ""
    else:
        if mode == "tunnel":
            trusted = _in(remote_addr or "", _LOOPBACK)
        elif mode == "direct":
            trusted = _in(remote_addr or "", ranges)
        else:
            raise UntrustedSource("unknown proxy mode")
        if not trusted:
            raise UntrustedSource("request did not come through Cloudflare")
        ip = (headers.get("CF-Connecting-IP") or "").strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise UntrustedSource("missing or invalid client IP") from exc


def cloudflare_says_tor(headers: Mapping[str, str]) -> bool:
    """Cloudflare sets CF-IPCountry to "T1" for Tor exit nodes (when IP
    geolocation is enabled on the zone)."""
    return (headers.get("CF-IPCountry") or "").upper() == "T1"


# ── VPN / proxy detection (offline IP2Proxy database) ─────────────────────────

_VPN_TYPES = {"VPN", "PUB", "WEB", "RES", "CPN", "EPN"}
_DC_TYPES = {"DCH", "SES"}


def empty_net(checked: bool = False) -> dict:
    return {"checked": checked, "vpn": False, "tor": False, "datacenter": False}


class VpnChecker:
    """Looks IPs up in a local IP2Proxy BIN file (e.g. the free IP2Proxy LITE
    PX2 database). Offline on purpose: the IP never goes to a third-party API.
    The IP2Proxy reader seeks in a shared file handle, so lookups are locked."""

    def __init__(self, db_path: str):
        import IP2Proxy  # imported here so tests don't need the package's file

        self._db = IP2Proxy.IP2Proxy()
        self._db.open(db_path)
        self._lock = threading.Lock()

    def check(self, ip: str) -> dict:
        with self._lock:
            status = self._db.is_proxy(ip)
            kind = self._db.get_proxy_type(ip) if status > 0 else "-"
        if status < 0:
            log.warning("VPN lookup failed (database error)")
            return empty_net(False)
        net = empty_net(True)
        kind = (kind or "-").upper()
        if kind == "TOR":
            net["tor"] = True
        elif kind in _DC_TYPES or status == 2:
            net["datacenter"] = True
        elif kind in _VPN_TYPES or status == 1:
            net["vpn"] = True
        return net


class DisabledVpnChecker:
    """Used only when VPN_CHECK=off. Every result says "not checked"."""

    def check(self, ip: str) -> dict:
        return empty_net(False)


# ── Cloudflare Turnstile ──────────────────────────────────────────────────────

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_ACTION = "verify"
TURNSTILE_MAX_AGE_SECONDS = 300


def verify_turnstile(secret: str, response: str, ip: str, *, cdata: str,
                     hostname: Optional[str], http=requests, now=None) -> bool:
    """Server-side Turnstile check. Fails closed on any error.

    Besides ``success`` we check the action, the cData (which binds the token to
    this one verification link), the hostname, and how old the challenge is.
    """
    if not response or len(response) > 2048:
        return False
    try:
        r = http.post(SITEVERIFY_URL, data={
            "secret": secret,
            "response": response,
            "remoteip": ip,
            "idempotency_key": str(uuid.uuid4()),
        }, timeout=5)
        data = r.json()
    except Exception:  # network error, bad JSON: fail closed
        log.warning("Turnstile siteverify request failed")
        return False
    if data.get("success") is not True:
        return False
    if data.get("action") != TURNSTILE_ACTION or data.get("cdata") != cdata:
        return False
    if hostname and data.get("hostname") != hostname:
        return False
    try:
        ts = datetime.fromisoformat(str(data.get("challenge_ts")).replace("Z", "+00:00"))
    except ValueError:
        return False
    now = now or datetime.now(timezone.utc)
    return 0 <= (now - ts).total_seconds() <= TURNSTILE_MAX_AGE_SECONDS
