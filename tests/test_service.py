import asyncio
from datetime import timedelta

import pytest
from mongomock_motor import AsyncMongoMockClient

from bot.service import Service, utcnow
from core import crypto

PRIV, PUB = crypto.generate_job_keypair()
GID = 111111111111111111
ALICE, ALT, BOB = 222222222222222222, 333333333333333333, 444444444444444444

BROWSER = {"device": "D" * 43, "canvas": "1" * 64, "webgl": "2" * 64, "audio": "3" * 64, "fonts": "4" * 64,
           "screen": "1920x1080x24@1", "tz": "Australia/Sydney", "lang": "en-AU,en", "platform": "Win32", "hw": "8|8"}
OTHER = {"device": "E" * 43, "canvas": "5" * 64, "webgl": "6" * 64, "audio": "7" * 64, "fonts": "8" * 64,
         "screen": "2560x1440x24@1", "tz": "Europe/Paris", "lang": "fr-FR", "platform": "MacIntel", "hw": "10|8"}
CLEAN = {"checked": True, "vpn": False, "tor": False, "datacenter": False}


def run(coro):
    return asyncio.run(coro)


async def make():
    db = AsyncMongoMockClient(tz_aware=True)["t"]
    kr = crypto.Keyring.parse(f"k1:{crypto.b64e(b'M' * 32)}")
    svc = Service(db, kr, PRIV)
    await svc.update_config(GID, verified_role_id=1, mod_channel_id=2)
    return svc


async def verify(svc, user_id, browser, net=CLEAN, uafam="windows-chrome"):
    """Simulate: bot makes a link, web page submits, bot processes the job."""
    token = await svc.create_session(GID, user_id)
    sid = crypto.session_id(token)
    await svc.sessions.update_one({"_id": sid}, {"$set": {"status": "submitted"}})
    payload = {"signals": browser, "net": net, "uafam": uafam}
    await svc.jobs.insert_one({"session_id": sid, "guild_id": GID, "sealed": crypto.seal_job(PUB, payload),
                               "created_at": utcnow(), "expires_at": utcnow() + timedelta(minutes=15)})
    job = await svc.claim_job()
    result = await svc.process_job(job)
    session = await svc.sessions.find_one({"_id": sid})
    return result, session["status"]


def test_clean_member_is_verified_and_nothing_raw_is_stored():
    async def t():
        svc = await make()
        result, status = await verify(svc, ALICE, BROWSER)
        assert result.action == "verify" and status == "verified" and result.user_id == ALICE
        rec = await svc.records.find_one({})
        text = repr(rec)
        assert str(ALICE) not in text  # Discord ID only stored encrypted
        for value in BROWSER.values():
            assert value not in text   # raw signals never stored
    run(t())


def test_alt_of_banned_user_goes_to_review_and_names_match_to_mods():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        assert await svc.on_ban(GID, ALICE)
        result, status = await verify(svc, ALT, BROWSER)
        assert result.action == "review" and status == "review"
        assert result.banned_match_user_id == ALICE and result.case_id
        # unrelated person is fine
        result, _ = await verify(svc, BOB, OTHER)
        assert result.action == "verify"
    run(t())


def test_alt_of_current_member_is_only_a_notice():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        result, _ = await verify(svc, ALT, BROWSER)
        assert result.action == "verify" and result.member_alt_user_ids == [ALICE]
    run(t())


def test_moderator_allow_stops_future_flags_for_that_pair():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.on_ban(GID, ALICE)
        result, _ = await verify(svc, ALT, BROWSER)
        assert await svc.resolve_case(GID, result.case_id, "allow") == ALT
        assert await svc.resolve_case(GID, result.case_id, "allow") is None  # already decided
        result, _ = await verify(svc, ALT, BROWSER)
        assert result.action == "verify"
    run(t())


def test_vpn_block_stores_nothing():
    async def t():
        svc = await make()
        await svc.update_config(GID, vpn_policy="block")
        result, status = await verify(svc, ALICE, BROWSER, net={**CLEAN, "vpn": True})
        assert result.action == "block" and status == "blocked"
        assert await svc.records.count_documents({}) == 0
    run(t())


def test_ios_needs_device_token_for_strong():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER, uafam="ios-safari")
        await svc.on_ban(GID, ALICE)
        # Same model iPhone, different person: everything but the device token matches.
        result, _ = await verify(svc, ALT, {**BROWSER, "device": "Z" * 43}, uafam="ios-safari")
        assert result.action == "review"  # strong downgraded to medium: still reviewed, not auto anything
        result, _ = await verify(svc, BOB, {**BROWSER, "device": "Y" * 43, "audio": "9" * 64}, uafam="ios-safari")
        assert result.action == "verify"  # medium downgraded to none
    run(t())


# ── deletion vs ban evasion ───────────────────────────────────────────────────

def test_member_can_delete_but_alt_deletion_does_not_erase_ban_evidence():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.on_ban(GID, ALICE)
        await verify(svc, ALT, BROWSER)            # alt flagged
        report = await svc.delete_user(ALT)        # alt deletes itself
        assert report.deleted_guild_ids == [GID]
        result, _ = await verify(svc, ALT, BROWSER)
        assert result.action == "review"           # still caught: the ban record is untouched
    run(t())


def test_banned_user_cannot_delete_ban_record():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.on_ban(GID, ALICE)
        report = await svc.delete_user(ALICE)
        assert report.deleted_guild_ids == [] and len(report.kept_bans) == 1
        assert (await svc.records.find_one({}))["status"] == "banned"
    run(t())


def test_delete_then_ban_in_grace_period_still_catches_alt():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.delete_user(ALICE)               # deletes right before moderators act
        rec = await svc.records.find_one({})
        assert rec["status"] == "deleting" and "user_ct" not in rec
        await svc.on_ban(GID, ALICE)               # banned within the grace period
        result, _ = await verify(svc, ALT, BROWSER)
        assert result.action == "review" and result.banned_match_user_id == ALICE
    run(t())


def test_deleted_member_is_not_matched_when_not_banned():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.delete_user(ALICE)
        result, _ = await verify(svc, ALT, BROWSER)
        assert result.action == "verify" and result.member_alt_user_ids == []
    run(t())


def test_unban_deletes_ban_record():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.on_ban(GID, ALICE)
        assert await svc.on_unban(GID, ALICE)
        assert await svc.records.count_documents({}) == 0
    run(t())


def test_leaving_shortens_retention():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.on_leave(GID, ALICE)
        rec = await svc.records.find_one({})
        assert rec["expires_at"] <= utcnow() + timedelta(days=31)
    run(t())


def test_shred_guild_removes_key_first_and_everything():
    async def t():
        svc = await make()
        await verify(svc, ALICE, BROWSER)
        await svc.on_ban(GID, ALICE)
        await svc.shred_guild(GID)
        for coll in (svc.guild_keys, svc.configs, svc.records, svc.cases, svc.sessions, svc.jobs):
            assert await coll.count_documents({}) == 0
    run(t())


def test_reconcile_waits_before_shredding():
    async def t():
        svc = await make()
        assert await svc.reconcile_guilds(set()) == []          # first time: only marked
        assert await svc.guild_keys.count_documents({}) == 1
        await svc.guild_keys.update_one({"_id": GID}, {"$set": {"missing_since": utcnow() - timedelta(hours=25)}})
        assert await svc.reconcile_guilds(set()) == [GID]
        assert await svc.guild_keys.count_documents({}) == 0
    run(t())


def test_new_link_invalidates_old_one():
    async def t():
        svc = await make()
        t1 = await svc.create_session(GID, ALICE)
        t2 = await svc.create_session(GID, ALICE)
        assert await svc.sessions.find_one({"_id": crypto.session_id(t1)}) is None
        assert await svc.sessions.find_one({"_id": crypto.session_id(t2)})
    run(t())


def test_tampered_job_is_rejected():
    async def t():
        svc = await make()
        token = await svc.create_session(GID, ALICE)
        sid = crypto.session_id(token)
        await svc.sessions.update_one({"_id": sid}, {"$set": {"status": "submitted"}})
        _, other_pub = crypto.generate_job_keypair()
        job = {"session_id": sid, "guild_id": GID, "sealed": crypto.seal_job(other_pub, {})}
        assert await svc.process_job(job) is None
        assert (await svc.sessions.find_one({"_id": sid}))["status"] == "error"
    run(t())


def test_config_validation():
    async def t():
        svc = await make()
        with pytest.raises(ValueError):
            await svc.update_config(GID, vpn_policy="maybe")
        with pytest.raises(ValueError):
            await svc.update_config(GID, ban_days=9999)
    run(t())
