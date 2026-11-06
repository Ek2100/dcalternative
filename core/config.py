"""Settings from environment variables. The web tier and the bot load
different settings, so each process only ever holds the secrets it needs:

* the web tier never sees the Discord token, master keys or job private key;
* the bot never sees the Turnstile secret.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from core.crypto import Keyring, b64d
from core.netcheck import PROXY_MODES


class ConfigError(Exception):
    pass


def _req(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is not set")
    return value


def _int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    return default if not raw else raw in ("1", "true", "yes", "on")


def _base_url() -> str:
    url = _req("PUBLIC_BASE_URL").rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme != "https" and not _bool("ALLOW_HTTP_BASE_URL"):
        raise ConfigError("PUBLIC_BASE_URL must start with https://")
    return url


@dataclass(frozen=True)
class Retention:
    """How long things live. Every collection also has a TTL index on
    ``expires_at`` so MongoDB deletes rows even if the bot is down."""

    session_minutes: int = 10      # verification links
    member_days: int = 180         # verified members, counted from verification
    left_days: int = 30            # after leaving (needs the members intent)
    ban_days_default: int = 180    # after a ban; each server can pick 30–365
    delete_grace_days: int = 7     # after a user asks for deletion (see README)
    case_days: int = 14            # open moderator cases
    missing_guild_hours: int = 24  # bot gone from a server for this long → shred


BAN_DAY_CHOICES = (30, 90, 180, 365)


@dataclass(frozen=True)
class WebSettings:
    mongo_uri: str
    db_name: str
    public_base_url: str
    turnstile_site_key: str
    turnstile_secret: str
    turnstile_hostname: str
    job_public_key: str
    proxy_mode: str
    cloudflare_ips_file: str
    vpn_check: bool
    ip2proxy_db: str
    session_minutes: int

    @classmethod
    def from_env(cls) -> "WebSettings":
        mode = os.getenv("PROXY_MODE", "tunnel").strip()
        if mode not in PROXY_MODES:
            raise ConfigError(f"PROXY_MODE must be one of {', '.join(PROXY_MODES)}")
        if mode == "insecure-dev" and not _bool("I_UNDERSTAND_THIS_IS_INSECURE"):
            raise ConfigError("PROXY_MODE=insecure-dev also needs I_UNDERSTAND_THIS_IS_INSECURE=1")
        vpn_check = os.getenv("VPN_CHECK", "on").strip().lower() != "off"
        public_key = _req("JOB_PUBLIC_KEY")
        if len(b64d(public_key)) != 32:
            raise ConfigError("JOB_PUBLIC_KEY is not a valid key")
        base = _base_url()
        return cls(
            mongo_uri=_req("MONGO_URI_WEB"),
            db_name=os.getenv("MONGO_DB", "verify").strip() or "verify",
            public_base_url=base,
            turnstile_site_key=_req("TURNSTILE_SITE_KEY"),
            turnstile_secret=_req("TURNSTILE_SECRET_KEY"),
            turnstile_hostname=os.getenv("TURNSTILE_HOSTNAME", urlparse(base).hostname or "").strip(),
            job_public_key=public_key,
            proxy_mode=mode,
            cloudflare_ips_file=os.getenv("CLOUDFLARE_IPS_FILE", "").strip(),
            vpn_check=vpn_check,
            ip2proxy_db=_req("IP2PROXY_DB") if vpn_check else "",
            session_minutes=Retention.session_minutes,
        )


@dataclass(frozen=True)
class BotSettings:
    discord_token: str
    mongo_uri: str
    db_name: str
    keyring: Keyring
    job_private_key: str
    public_base_url: str
    use_members_intent: bool
    sync_commands: bool
    shard_count: int
    retention: Retention

    @classmethod
    def from_env(cls) -> "BotSettings":
        private_key = _req("JOB_PRIVATE_KEY")
        if len(b64d(private_key)) != 32:
            raise ConfigError("JOB_PRIVATE_KEY is not a valid key")
        try:
            keyring = Keyring.parse(_req("MASTER_KEYS"))
        except Exception as exc:
            raise ConfigError(f"MASTER_KEYS is invalid: {exc}") from None
        retention = Retention(
            member_days=_int("MEMBER_RETENTION_DAYS", Retention.member_days, 7, 365),
            left_days=_int("LEFT_RETENTION_DAYS", Retention.left_days, 1, 90),
            delete_grace_days=_int("DELETE_GRACE_DAYS", Retention.delete_grace_days, 0, 14),
        )
        return cls(
            discord_token=_req("DISCORD_TOKEN"),
            mongo_uri=_req("MONGO_URI_BOT"),
            db_name=os.getenv("MONGO_DB", "verify").strip() or "verify",
            keyring=keyring,
            job_private_key=private_key,
            public_base_url=_base_url(),
            use_members_intent=_bool("USE_MEMBERS_INTENT"),
            sync_commands=_bool("SYNC_COMMANDS"),
            shard_count=_int("SHARD_COUNT", 0, 0, 1000),
            retention=retention,
        )
