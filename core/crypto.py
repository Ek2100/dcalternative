"""All the cryptography the verification bot uses. Pure functions, no I/O.

How the keys fit together
-------------------------
* Master keys (``MASTER_KEYS`` env, bot only) wrap each server's key with
  AES-256-GCM. Several can be listed so the master key can be rotated.
* Every server ("guild") gets its own random 256-bit key. Two sub-keys are
  derived from it: one for keyed hashes (HMAC-SHA-256) and one for encryption
  (AES-256-GCM).
* Browser signals are stored only as HMACs under the server's key. The same
  browser in two different servers produces unrelated values, so nobody (us
  included) can link people across servers.
* Discord user IDs are stored encrypted under the server's key, plus a keyed
  "uid tag" so a user's rows can be found for deletion without decrypting.
* Deleting a server's wrapped key makes every row for that server permanently
  unreadable ("crypto-shredding"), including copies in backups.

Raw signals travel from the web tier to the bot sealed with a libsodium sealed
box: the web tier holds only the public key, so it cannot read old jobs back.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl.exceptions import CryptoError as NaclCryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

KEY_BYTES = 32
NONCE_BYTES = 12
_KID_RE = re.compile(r"[a-z0-9]{1,16}")


class CryptoError(Exception):
    """Decryption failed or a key is malformed. Never carries secret material."""


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    text = text.strip().replace("+", "-").replace("/", "_")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise CryptoError("invalid base64") from exc


# ── Master keyring ────────────────────────────────────────────────────────────

def _guild_aad(guild_id: int) -> bytes:
    return b"guild-key:v1:" + str(int(guild_id)).encode()


class Keyring:
    """Master keys that wrap per-server keys. The first key is the current one."""

    def __init__(self, keys: dict[str, bytes], current: str):
        if current not in keys:
            raise CryptoError("current master key id is not in the keyring")
        for kid, key in keys.items():
            if not _KID_RE.fullmatch(kid) or len(key) != KEY_BYTES:
                raise CryptoError("master keys must be 32 bytes with ids of a-z0-9")
        self._keys = dict(keys)
        self.current = current

    @classmethod
    def parse(cls, spec: str) -> "Keyring":
        """Parse ``"kid:base64key,kid2:base64key"``; the first entry is current."""
        keys: dict[str, bytes] = {}
        order: list[str] = []
        for part in (spec or "").split(","):
            part = part.strip()
            if not part:
                continue
            kid, sep, value = part.partition(":")
            if not sep:
                raise CryptoError("MASTER_KEYS entries must look like kid:base64key")
            if kid in keys:
                raise CryptoError("duplicate master key id")
            keys[kid] = b64d(value)
            order.append(kid)
        if not order:
            raise CryptoError("MASTER_KEYS is empty")
        return cls(keys, order[0])

    def wrap(self, guild_id: int, raw_key: bytes) -> dict:
        if len(raw_key) != KEY_BYTES:
            raise CryptoError("server keys must be 32 bytes")
        nonce = secrets.token_bytes(NONCE_BYTES)
        ct = AESGCM(self._keys[self.current]).encrypt(nonce, raw_key, _guild_aad(guild_id))
        return {"kid": self.current, "nonce": nonce, "ct": ct}

    def unwrap(self, guild_id: int, wrapped: dict) -> bytes:
        key = self._keys.get(wrapped.get("kid"))
        if key is None:
            raise CryptoError("server key was wrapped with an unknown master key")
        try:
            return AESGCM(key).decrypt(bytes(wrapped["nonce"]), bytes(wrapped["ct"]), _guild_aad(guild_id))
        except (InvalidTag, KeyError, TypeError, ValueError) as exc:
            raise CryptoError("could not unwrap server key") from exc

    def needs_rewrap(self, wrapped: dict) -> bool:
        return wrapped.get("kid") != self.current


def new_guild_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


# ── Per-server key ────────────────────────────────────────────────────────────

class GuildKey:
    """One server's key. Hashes signals, tags and encrypts user IDs."""

    def __init__(self, guild_id: int, raw_key: bytes):
        if len(raw_key) != KEY_BYTES:
            raise CryptoError("server keys must be 32 bytes")
        self.guild_id = int(guild_id)
        # Separate sub-keys so the same key is never used for MAC and encryption.
        self._mac = hmac.new(raw_key, b"syntaxhq-verify:mac:v1", hashlib.sha256).digest()
        self._enc = hmac.new(raw_key, b"syntaxhq-verify:enc:v1", hashlib.sha256).digest()

    def _hmac(self, data: bytes) -> str:
        return hmac.new(self._mac, data, hashlib.sha256).hexdigest()

    def sig(self, name: str, value: Optional[str]) -> Optional[str]:
        """Keyed hash of one browser signal. Missing values are never hashed:
        hashing "" would make every browser without that signal look identical."""
        if not value:
            return None
        return self._hmac(b"sig:" + name.encode() + b":" + value.encode())

    def uid_tag(self, user_id: int) -> str:
        return self._hmac(b"uid:" + str(int(user_id)).encode())

    def _seal(self, plaintext: bytes, purpose: bytes) -> bytes:
        nonce = secrets.token_bytes(NONCE_BYTES)
        aad = purpose + b":" + str(self.guild_id).encode()
        return nonce + AESGCM(self._enc).encrypt(nonce, plaintext, aad)

    def _open(self, blob: bytes, purpose: bytes) -> bytes:
        blob = bytes(blob)
        aad = purpose + b":" + str(self.guild_id).encode()
        try:
            return AESGCM(self._enc).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)
        except (InvalidTag, ValueError) as exc:
            raise CryptoError("could not decrypt") from exc

    def seal_uid(self, user_id: int) -> bytes:
        return self._seal(str(int(user_id)).encode(), b"uid:v1")

    def open_uid(self, blob: bytes) -> int:
        return int(self._open(blob, b"uid:v1").decode())

    def seal_text(self, text: str) -> bytes:
        return self._seal(text.encode("utf-8"), b"text:v1")

    def open_text(self, blob: bytes) -> str:
        return self._open(blob, b"text:v1").decode("utf-8")


# ── One-time verification links ───────────────────────────────────────────────

_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")


def new_session_token() -> tuple[str, str]:
    """Return (token for the link, id stored in the database). Only the SHA-256
    of the token is stored, so a database dump cannot be turned into links."""
    token = secrets.token_urlsafe(32)  # 43 chars
    return token, session_id(token)


def session_id(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def valid_token_format(token: str) -> bool:
    return bool(_TOKEN_RE.fullmatch(token or ""))


# ── Sealed jobs (web → bot) ───────────────────────────────────────────────────

def generate_job_keypair() -> tuple[str, str]:
    """Return (private_b64, public_b64)."""
    private = PrivateKey.generate()
    return b64e(bytes(private)), b64e(bytes(private.public_key))


def seal_job(public_key_b64: str, payload: dict) -> bytes:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return SealedBox(PublicKey(b64d(public_key_b64))).encrypt(data)


def open_job(private_key_b64: str, blob: bytes) -> dict:
    try:
        data = SealedBox(PrivateKey(b64d(private_key_b64))).decrypt(bytes(blob))
        payload = json.loads(data)
    except (NaclCryptoError, ValueError, TypeError) as exc:
        raise CryptoError("could not open job") from exc
    if not isinstance(payload, dict):
        raise CryptoError("job payload is not an object")
    return payload
