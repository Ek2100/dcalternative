"""The bot's brain: verification sessions, matching, moderator cases, bans and
deletion. main.py calls into this from Discord events and buttons; keeping it
here (without discord.py objects) is what lets tests/ exercise every rule.

Deletion without letting people delete their alts' evidence
-----------------------------------------------------------
The thing that catches ban evasion is the *banned* account's record. So:

* A member can delete their data at any time. Their verified role is removed
  immediately, and their record is unreadable at once: the encrypted Discord ID
  is wiped and the record is never matched against again. The leftover hashes
  are purged after DELETE_GRACE_DAYS (7 by default).
* If that account is banned during the grace period, the record becomes a ban
  record. Otherwise "break the rules, delete, get banned, come back on an alt"
  would beat the system.
* A ban record cannot be deleted by the banned user. It expires on the
  server's schedule (default 180 days), or straight away if the server unbans
  them or removes the bot. Moderators control it, not the person it's about.
* Deleting an *alt's* data only un-verifies the alt. It doesn't touch the ban
  record, so the alt still matches next time it verifies.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from bson import ObjectId

from core.config import BAN_DAY_CHOICES, Retention
from core.crypto import (CryptoError, GuildKey, Keyring, new_guild_key,
                         new_session_token, open_job)
from core.matching import (MEDIUM, VPN_POLICIES, Match, candidate_query,
                           compare, decide)
from core.netcheck import empty_net
from core.signals import SIGNAL_NAMES, clean_signals, clean_uafam, is_ios

log = logging.getLogger("verify.service")

LIVE_STATUSES = ("verified", "pending", "denied")   # records of people in the server
MATCHABLE = ("verified", "banned")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


DEFAULT_CONFIG = {
    "verified_role_id": None,
    "mod_channel_id": None,
    "verify_channel_id": None,
    "vpn_policy": "review",
    "ban_days": 180,
    "dm_on_join": True,
    "alt_notices": True,
}


@dataclass
class JobResult:
    guild_id: int
    user_id: int
    session_id: str
    action: str                                    # verify | review | block | error
    reasons: list[str] = field(default_factory=list)
    case_id: Optional[str] = None
    banned_match_user_id: Optional[int] = None
    banned_match_at: Optional[datetime] = None
    match_reasons: tuple[str, ...] = ()
    member_alt_user_ids: list[int] = field(default_factory=list)
    net: dict = field(default_factory=dict)


@dataclass
class DeletionReport:
    deleted_guild_ids: list[int] = field(default_factory=list)       # remove verified role here
    kept_bans: list[tuple[int, datetime]] = field(default_factory=list)
    already_deleting: list[int] = field(default_factory=list)
    purge_after: Optional[datetime] = None


class Service:
    def __init__(self, db, keyring: Keyring, job_private_key: str, retention: Retention = Retention()):
        self.db = db
        self.keyring = keyring
        self.job_private_key = job_private_key
        self.retention = retention
        self.guild_keys = db["guild_keys"]
        self.configs = db["guild_configs"]
        self.sessions = db["verify_sessions"]
        self.jobs = db["verify_jobs"]
        self.records = db["records"]
        self.cases = db["cases"]
        self._key_cache: dict[int, tuple[float, GuildKey]] = {}

    # ── setup ────────────────────────────────────────────────────────────────

    async def ensure_indexes(self) -> None:
        for coll in (self.sessions, self.jobs, self.records, self.cases):
            # MongoDB deletes each document once expires_at has passed.
            await coll.create_index("expires_at", expireAfterSeconds=0)
        await self.records.create_index([("guild_id", 1), ("uid_tag", 1)], unique=True)
        await self.records.create_index("uid_tag")
        for name in ("device", "canvas", "webgl", "audio", "fonts"):
            await self.records.create_index([("guild_id", 1), (f"sig.{name}", 1)], sparse=True)
        await self.sessions.create_index("uid_tag")
        await self.jobs.create_index("created_at")
        await self.cases.create_index([("guild_id", 1), ("subject_tag", 1)])

    # ── keys and config ──────────────────────────────────────────────────────

    async def guild_key(self, guild_id: int, *, create: bool = False) -> Optional[GuildKey]:
        cached = self._key_cache.get(guild_id)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        doc = await self.guild_keys.find_one({"_id": guild_id})
        if doc is None:
            if not create:
                return None
            raw = new_guild_key()
            wrapped = self.keyring.wrap(guild_id, raw)
            try:
                await self.guild_keys.insert_one({"_id": guild_id, **wrapped, "created_at": utcnow()})
            except Exception:
                # Another task created it first: use theirs.
                doc = await self.guild_keys.find_one({"_id": guild_id})
                raw = self.keyring.unwrap(guild_id, doc)
        else:
            raw = self.keyring.unwrap(guild_id, doc)
            if self.keyring.needs_rewrap(doc):
                await self.guild_keys.update_one({"_id": guild_id}, {"$set": self.keyring.wrap(guild_id, raw)})
        key = GuildKey(guild_id, raw)
        self._key_cache[guild_id] = (time.monotonic() + 600, key)
        return key

    async def get_config(self, guild_id: int) -> dict:
        doc = await self.configs.find_one({"_id": guild_id}) or {}
        return {**DEFAULT_CONFIG, **{k: v for k, v in doc.items() if k in DEFAULT_CONFIG}}

    async def update_config(self, guild_id: int, **changes) -> dict:
        allowed = {k: v for k, v in changes.items() if k in DEFAULT_CONFIG}
        if "vpn_policy" in allowed and allowed["vpn_policy"] not in VPN_POLICIES:
            raise ValueError("bad VPN policy")
        if "ban_days" in allowed and allowed["ban_days"] not in BAN_DAY_CHOICES:
            raise ValueError("bad ban retention")
        await self.guild_key(guild_id, create=True)
        await self.configs.update_one({"_id": guild_id}, {"$set": allowed}, upsert=True)
        return await self.get_config(guild_id)

    @staticmethod
    def is_ready(config: dict) -> bool:
        return bool(config.get("verified_role_id") and config.get("mod_channel_id"))

    # ── verification links ───────────────────────────────────────────────────

    async def create_session(self, guild_id: int, user_id: int) -> str:
        """Make a one-time link token. Any older unused links for this user in
        this server stop working, so only the newest link is ever valid."""
        key = await self.guild_key(guild_id, create=True)
        tag = key.uid_tag(user_id)
        await self.sessions.delete_many({"guild_id": guild_id, "uid_tag": tag, "status": "new"})
        token, sid = new_session_token()
        now = utcnow()
        await self.sessions.insert_one({
            "_id": sid,
            "guild_id": guild_id,
            "uid_tag": tag,
            "user_ct": key.seal_uid(user_id),
            "status": "new",
            "created_at": now,
            "expires_at": now + timedelta(minutes=self.retention.session_minutes),
        })
        return token

    async def set_session_status(self, session_id: str, status: str) -> None:
        await self.sessions.update_one({"_id": session_id}, {"$set": {"status": status}})

    # ── processing submitted verifications ───────────────────────────────────

    async def claim_job(self) -> Optional[dict]:
        return await self.jobs.find_one_and_delete({}, sort=[("created_at", 1)])

    async def process_job(self, job: dict) -> Optional[JobResult]:
        sid = job.get("session_id")
        gid = job.get("guild_id")
        session = await self.sessions.find_one({"_id": sid, "status": "submitted"})
        if not session or session.get("guild_id") != gid:
            return None
        key = await self.guild_key(gid)
        config = await self.get_config(gid)
        if key is None or not self.is_ready(config):
            await self.set_session_status(sid, "error")
            return None
        try:
            payload = open_job(self.job_private_key, job["sealed"])
            user_id = key.open_uid(session["user_ct"])
        except (CryptoError, KeyError, ValueError):
            log.warning("could not open a verification job (guild %s)", gid)
            await self.set_session_status(sid, "error")
            return None

        # Re-validate everything: the bot doesn't trust the web tier either.
        signals = clean_signals(payload.get("signals"))
        signals["uafam"] = clean_uafam(payload.get("uafam"))
        raw_net = payload.get("net") if isinstance(payload.get("net"), dict) else {}
        net = {k: raw_net.get(k) is True for k in empty_net()}
        ios = is_ios(signals["uafam"])

        tag = key.uid_tag(user_id)
        sig = {n: key.sig(n, signals.get(n)) for n in SIGNAL_NAMES}
        sig = {n: v for n, v in sig.items() if v}
        del signals, payload  # raw values are not needed past this point

        existing = await self.records.find_one({"guild_id": gid, "uid_tag": tag})
        allow = set(existing.get("allow", [])) if existing else set()

        banned: list[tuple[dict, Match]] = []
        members: list[tuple[dict, Match]] = []
        clauses = candidate_query(sig)
        if clauses:
            cursor = self.records.find({
                "guild_id": gid, "uid_tag": {"$ne": tag},
                "status": {"$in": list(MATCHABLE)}, "$or": clauses,
            }).limit(50)
            async for cand in cursor:
                if cand["_id"] in allow:
                    continue
                m = compare(sig, cand.get("sig", {}), ios=ios or bool(cand.get("ios")))
                if m.level >= MEDIUM:
                    (banned if cand["status"] == "banned" else members).append((cand, m))

        outcome = decide(net=net, vpn_policy=config["vpn_policy"], banned_matches=[m for _, m in banned])
        result = JobResult(gid, user_id, sid, outcome.action, outcome.reasons, net=net)
        now = utcnow()

        if outcome.action == "block":
            # Blocked for VPN: nothing about this attempt is stored.
            await self.set_session_status(sid, "blocked")
            return result

        status = "verified" if outcome.action == "verify" else "pending"
        res = await self.records.find_one_and_update(
            {"guild_id": gid, "uid_tag": tag},
            {"$set": {
                "sig": sig, "ios": ios, "user_ct": key.seal_uid(user_id), "status": status,
                "verified_at": now, "expires_at": now + timedelta(days=self.retention.member_days),
            }, "$setOnInsert": {"guild_id": gid, "uid_tag": tag, "allow": []},
             "$unset": {"deletion_requested_at": ""}},
            upsert=True, return_document=True,
        )
        record_id = res["_id"] if res else None

        if config["alt_notices"]:
            for cand, _ in members[:5]:
                try:
                    result.member_alt_user_ids.append(key.open_uid(cand["user_ct"]))
                except (CryptoError, KeyError):
                    pass

        if outcome.action == "review":
            best = max(banned, key=lambda cm: cm[1].level, default=None)
            case = {
                "guild_id": gid, "kind": "match" if best else "network",
                "subject_tag": tag, "subject_ct": key.seal_uid(user_id), "record_id": record_id,
                "reasons": outcome.reasons, "status": "open", "created_at": now,
                "expires_at": now + timedelta(days=self.retention.case_days),
            }
            if best:
                cand, m = best
                case["matched_id"] = cand["_id"]
                result.match_reasons = m.reasons
                result.banned_match_at = _aware(cand.get("banned_at"))
                try:
                    result.banned_match_user_id = key.open_uid(cand["user_ct"])
                except (CryptoError, KeyError):
                    pass
            ins = await self.cases.insert_one(case)
            result.case_id = str(ins.inserted_id)
            await self.set_session_status(sid, "review")
        else:
            await self.set_session_status(sid, "verified")
        return result

    # ── moderator cases ──────────────────────────────────────────────────────

    async def create_manual_case(self, guild_id: int, user_id: int, note: str) -> str:
        key = await self.guild_key(guild_id, create=True)
        now = utcnow()
        tag = key.uid_tag(user_id)
        await self.cases.delete_many({"guild_id": guild_id, "subject_tag": tag, "kind": "manual"})
        ins = await self.cases.insert_one({
            "guild_id": guild_id, "kind": "manual", "subject_tag": tag,
            "subject_ct": key.seal_uid(user_id),
            "note_ct": key.seal_text(note[:300]) if note else None,
            "status": "open", "created_at": now,
            "expires_at": now + timedelta(days=self.retention.case_days),
        })
        return str(ins.inserted_id)

    async def resolve_case(self, guild_id: int, case_id: str, action: str) -> Optional[int]:
        """Allow or deny a case. Returns the subject's user ID, or None if the
        case is gone. The case is deleted once decided; the mod message stays."""
        if action not in ("allow", "deny") or not ObjectId.is_valid(case_id):
            return None
        case = await self.cases.find_one_and_delete({"_id": ObjectId(case_id), "guild_id": guild_id})
        key = await self.guild_key(guild_id)
        if not case or not key:
            return None
        user_id = key.open_uid(case["subject_ct"])
        if case.get("record_id"):
            update = {"$set": {"status": "verified" if action == "allow" else "denied"}}
            if action == "allow" and case.get("matched_id"):
                update["$addToSet"] = {"allow": case["matched_id"]}
            await self.records.update_one(
                {"_id": case["record_id"], "status": {"$in": ["pending", "verified", "denied"]}}, update)
        return user_id

    # ── membership events ────────────────────────────────────────────────────

    async def on_ban(self, guild_id: int, user_id: int) -> bool:
        """Turn the account's record (in any state, including mid-deletion) into
        a ban record. Returns True if there was a record."""
        key = await self.guild_key(guild_id)
        if key is None:
            return False
        config = await self.get_config(guild_id)
        now = utcnow()
        res = await self.records.update_one(
            {"guild_id": guild_id, "uid_tag": key.uid_tag(user_id)},
            {"$set": {"status": "banned", "banned_at": now, "user_ct": key.seal_uid(user_id),
                      "expires_at": now + timedelta(days=config["ban_days"])},
             "$unset": {"deletion_requested_at": ""}},
        )
        return res.matched_count > 0

    async def on_unban(self, guild_id: int, user_id: int) -> bool:
        key = await self.guild_key(guild_id)
        if key is None:
            return False
        res = await self.records.delete_one(
            {"guild_id": guild_id, "uid_tag": key.uid_tag(user_id), "status": "banned"})
        return res.deleted_count > 0

    async def on_leave(self, guild_id: int, user_id: int) -> None:
        key = await self.guild_key(guild_id)
        if key is None:
            return
        tag = key.uid_tag(user_id)
        await self.records.update_one(
            {"guild_id": guild_id, "uid_tag": tag, "status": {"$in": list(LIVE_STATUSES)}},
            {"$min": {"expires_at": utcnow() + timedelta(days=self.retention.left_days)}},
        )
        await self.sessions.delete_many({"guild_id": guild_id, "uid_tag": tag})

    # ── a user's own data ────────────────────────────────────────────────────

    async def _user_tags(self, user_id: int) -> dict[str, int]:
        tags: dict[str, int] = {}
        async for doc in self.guild_keys.find({}, {"_id": 1}):
            key = await self.guild_key(doc["_id"])
            if key:
                tags[key.uid_tag(user_id)] = doc["_id"]
        return tags

    async def user_overview(self, user_id: int) -> list[dict]:
        tags = await self._user_tags(user_id)
        out = []
        if not tags:
            return out
        async for rec in self.records.find({"uid_tag": {"$in": list(tags)}}):
            if tags.get(rec["uid_tag"]) != rec["guild_id"]:
                continue
            out.append({"guild_id": rec["guild_id"], "status": rec["status"],
                        "expires_at": _aware(rec.get("expires_at"))})
        return out

    async def delete_user(self, user_id: int) -> DeletionReport:
        report = DeletionReport()
        tags = await self._user_tags(user_id)
        if not tags:
            return report
        now = utcnow()
        purge_at = now + timedelta(days=self.retention.delete_grace_days)
        report.purge_after = purge_at
        tag_list = list(tags)

        async for rec in self.records.find({"uid_tag": {"$in": tag_list}}):
            gid = rec["guild_id"]
            if tags.get(rec["uid_tag"]) != gid:
                continue
            if rec["status"] == "banned":
                report.kept_bans.append((gid, _aware(rec.get("expires_at"))))
                continue
            if rec["status"] == "deleting":
                report.already_deleting.append(gid)
                continue
            if self.retention.delete_grace_days == 0:
                await self.records.delete_one({"_id": rec["_id"]})
            else:
                await self.records.update_one({"_id": rec["_id"]}, {
                    "$set": {"status": "deleting", "deletion_requested_at": now, "expires_at": purge_at,
                             "allow": []},
                    "$unset": {"user_ct": "", "verified_at": ""},
                })
            report.deleted_guild_ids.append(gid)

        await self.sessions.delete_many({"uid_tag": {"$in": tag_list}})
        await self.cases.delete_many({"subject_tag": {"$in": tag_list}})
        return report

    # ── a whole server's data ────────────────────────────────────────────────

    async def shred_guild(self, guild_id: int) -> dict:
        """Delete the server's key first (crypto-shred), then every row."""
        await self.guild_keys.delete_one({"_id": guild_id})
        self._key_cache.pop(guild_id, None)
        counts = {}
        for name, coll in (("records", self.records), ("cases", self.cases),
                           ("sessions", self.sessions), ("jobs", self.jobs)):
            counts[name] = (await coll.delete_many({"guild_id": guild_id})).deleted_count
        await self.configs.delete_one({"_id": guild_id})
        return counts

    async def reconcile_guilds(self, present: set[int]) -> list[int]:
        """Shred servers the bot has been missing from for a day (e.g. it was
        removed while offline). The delay avoids shredding on a bad startup."""
        now = utcnow()
        shredded = []
        async for doc in self.guild_keys.find({}, {"_id": 1, "missing_since": 1}):
            gid = doc["_id"]
            if gid in present:
                if doc.get("missing_since"):
                    await self.guild_keys.update_one({"_id": gid}, {"$unset": {"missing_since": ""}})
                continue
            since = _aware(doc.get("missing_since"))
            if since is None:
                await self.guild_keys.update_one({"_id": gid}, {"$set": {"missing_since": now}})
            elif now - since >= timedelta(hours=self.retention.missing_guild_hours):
                await self.shred_guild(gid)
                shredded.append(gid)
        return shredded

    async def stats(self, guild_id: int) -> dict:
        out = {}
        for status in ("verified", "pending", "denied", "banned", "deleting"):
            out[status] = await self.records.count_documents({"guild_id": guild_id, "status": status})
        out["open_cases"] = await self.cases.count_documents({"guild_id": guild_id})
        return out
