"""SyntaxHQ verification bot: the Discord side.

Run with:  python -m bot.main

What it does
------------
* Server added  → DMs the owner an onboarding guide (falls back to the system channel).
* /setup        → admin panel: verified role, mod-review channel, VPN policy,
                  ban-record retention, welcome DM on/off, alt notices on/off,
                  post the verify message, delete all server data.
* Member joins  → DM with a one-time verify link and a "new link" button.
                  Members with DMs closed use the Verify button in the server.
* Verify page   → consent → Cloudflare Turnstile → browser checks (web/ app).
* Result        → role given, or a case posted for moderators (Allow / Keep out).
* Bans/unbans   → ban records kept or cleared (see bot/service.py for why).
* /privacy      → see and delete your own data.
* Bot removed   → the server's key and all its data are deleted immediately.

The bot has no inbound ports, just like PinPal: it only talks out to Discord
and MongoDB. The web page writes sealed jobs that this process picks up.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from typing import Optional

import discord
from discord import app_commands
from discord.ext import tasks
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

from bot.service import Service, utcnow
from core.config import BAN_DAY_CHOICES, BotSettings, ConfigError

log = logging.getLogger("verify.bot")

BRAND = 0x5865F2
OK = 0x2ECC71
WARN = 0xF1C40F
BAD = 0xE74C3C
NO_MENTIONS = discord.AllowedMentions.none()

# Permissions the verified role must NOT have: we never hand out moderator powers.
DANGEROUS = discord.Permissions(
    administrator=True, ban_members=True, kick_members=True, manage_guild=True,
    manage_roles=True, manage_channels=True, manage_messages=True, manage_webhooks=True,
    mention_everyone=True, moderate_members=True, manage_nicknames=True,
    manage_expressions=True, manage_events=True, manage_threads=True,
)
# View Channel, Send Messages, Embed Links, Manage Roles. Nothing else: a stolen
# token can't ban, kick, delete messages or change the server.
INVITE_PERMISSIONS = 268453504

VPN_LABELS = {
    "allow": "Allow VPNs",
    "review": "Send VPN users to moderator review",
    "block": "Block VPNs (ask them to turn it off)",
}


# ── helpers ───────────────────────────────────────────────────────────────────

class Cooldowns:
    """In-memory per-user cooldowns. Nothing is persisted."""

    def __init__(self):
        self._last: dict[tuple[str, int], float] = {}

    def hit(self, action: str, user_id: int, seconds: float) -> float:
        """Return seconds left to wait (0 if allowed, and records the use)."""
        now = time.monotonic()
        last = self._last.get((action, user_id), 0.0)
        if now - last < seconds:
            return seconds - (now - last)
        self._last[(action, user_id)] = now
        if len(self._last) > 50_000:
            self._last = {k: v for k, v in self._last.items() if now - v < 600}
        return 0.0


def role_problem(role: discord.Role, me: discord.Member) -> Optional[str]:
    if role.is_default():
        return "That's @everyone. Pick (or create) a role like **Verified**."
    if role.managed:
        return "That role belongs to a bot or integration. Pick a normal role."
    if role.permissions.value & DANGEROUS.value:
        return ("That role has moderator permissions (like Ban, Kick, Manage or Administrator). "
                "I only hand out plain roles. Pick a role without those permissions.")
    if not me.guild_permissions.manage_roles:
        return "I need the **Manage Roles** permission to give that role."
    if role >= me.top_role:
        return (f"My highest role must be **above** {role.mention}. Go to Server Settings → Roles "
                "and drag my role above it.")
    return None


def channel_problem(channel: discord.abc.GuildChannel, me: discord.Member) -> Optional[str]:
    perms = channel.permissions_for(me)
    missing = [n for n, ok in (("View Channel", perms.view_channel), ("Send Messages", perms.send_messages),
                                ("Embed Links", perms.embed_links)) if not ok]
    if missing:
        return f"I'm missing {', '.join(missing)} in {channel.mention}."
    return None


def is_mod(member: discord.Member) -> bool:
    p = member.guild_permissions
    return p.manage_guild or p.ban_members or p.manage_roles or p.administrator


def fmt_date(dt) -> str:
    return discord.utils.format_dt(dt, "D") if dt else "unknown"


# ── the client ────────────────────────────────────────────────────────────────

class VerifyBot(discord.AutoShardedClient):
    def __init__(self, settings: BotSettings, service: Service):
        intents = discord.Intents.none()
        intents.guilds = True
        intents.members = True      # privileged: needed for join DMs and leave handling
        intents.moderation = True   # ban / unban events
        kwargs = {"shard_count": settings.shard_count} if settings.shard_count else {}
        super().__init__(intents=intents, chunk_guilds_at_startup=False,
                         allowed_mentions=NO_MENTIONS, **kwargs)
        self.settings = settings
        self.service = service
        self.tree = app_commands.CommandTree(self)
        self.cooldowns = Cooldowns()
        self.dm_semaphore = asyncio.Semaphore(5)

    async def setup_hook(self) -> None:
        await self.service.ensure_indexes()
        self.add_view(VerifyMessageView())
        self.add_dynamic_items(CaseButton, NewLinkButton)
        register_commands(self)
        if self.settings.sync_commands:
            synced = await self.tree.sync()
            log.info("synced %d commands", len(synced))
        self.process_jobs.start()
        self.reconcile.start()

    def link_for(self, token: str) -> str:
        return f"{self.settings.public_base_url}/v/{token}"

    # ── background loops ─────────────────────────────────────────────────────

    @tasks.loop(seconds=2)
    async def process_jobs(self):
        for _ in range(25):
            job = await self.service.claim_job()
            if not job:
                return
            try:
                result = await self.service.process_job(job)
                if result:
                    await self.apply_result(result)
            except Exception:
                log.exception("failed to process a verification job (guild %s)", job.get("guild_id"))
                if job.get("session_id"):
                    await self.service.set_session_status(job["session_id"], "error")

    @process_jobs.before_loop
    async def _wait_jobs(self):
        await self.wait_until_ready()

    @tasks.loop(hours=1)
    async def reconcile(self):
        shredded = await self.service.reconcile_guilds({g.id for g in self.guilds})
        if shredded:
            log.info("deleted data for %d servers the bot is no longer in", len(shredded))

    @reconcile.before_loop
    async def _wait_reconcile(self):
        await self.wait_until_ready()
        await asyncio.sleep(300)  # let every shard settle before deciding a server is gone

    async def apply_result(self, result) -> None:
        guild = self.get_guild(result.guild_id)
        config = await self.service.get_config(result.guild_id)
        if guild is None:
            return
        mod_channel = guild.get_channel(config["mod_channel_id"] or 0)

        if result.action == "verify":
            try:
                await self.http.add_role(guild.id, result.user_id, config["verified_role_id"],
                                         reason="Passed verification")
            except discord.HTTPException:
                await self.service.set_session_status(result.session_id, "error")
                if mod_channel:
                    await mod_channel.send(embed=discord.Embed(
                        color=BAD, title="I couldn't give the verified role",
                        description=(f"<@{result.user_id}> passed verification but I couldn't give them "
                                     f"<@&{config['verified_role_id']}>. Check my role is above it and I "
                                     "have Manage Roles, then run `/setup`.")))
        elif result.action == "review" and mod_channel and result.case_id:
            await mod_channel.send(embed=case_embed(result), view=case_view(result.case_id))

        if result.member_alt_user_ids and mod_channel and config["alt_notices"]:
            others = ", ".join(f"<@{u}>" for u in result.member_alt_user_ids)
            await mod_channel.send(embed=discord.Embed(
                color=WARN, title="Heads up: possible second account",
                description=(f"<@{result.user_id}> verified from what looks like the same browser or "
                             f"device as {others}. They're not banned, so nothing was blocked. Families "
                             "and shared computers can cause this. Turn these notices off in `/setup`.")))

    # ── events ───────────────────────────────────────────────────────────────

    async def on_ready(self):
        log.info("ready in %d servers", len(self.guilds))

    async def on_guild_join(self, guild: discord.Guild):
        embed = onboarding_embed(guild, self.settings.public_base_url)
        try:
            owner = guild.owner or await self.fetch_user(guild.owner_id)
            await owner.send(embed=embed)
            return
        except (discord.HTTPException, AttributeError):
            pass
        channel = guild.system_channel
        if channel and channel.permissions_for(guild.me).send_messages:
            try:
                await channel.send(embed=embed)
            except discord.HTTPException:
                pass

    async def on_guild_remove(self, guild: discord.Guild):
        counts = await self.service.shred_guild(guild.id)
        log.info("removed from a server: deleted its key and %d records", counts.get("records", 0))

    async def on_member_join(self, member: discord.Member):
        if member.bot:
            return
        config = await self.service.get_config(member.guild.id)
        if not (Service.is_ready(config) and config["dm_on_join"]):
            return
        async with self.dm_semaphore:
            token = await self.service.create_session(member.guild.id, member.id)
            try:
                await member.send(embed=welcome_embed(member.guild),
                                  view=link_view(self.link_for(token), member.guild.id))
            except discord.HTTPException:
                pass  # DMs closed: they can use the Verify button in the server

    async def on_member_remove(self, member: discord.Member):
        await self.service.on_leave(member.guild.id, member.id)

    async def on_member_ban(self, guild: discord.Guild, user: discord.abc.User):
        await self.service.on_ban(guild.id, user.id)

    async def on_member_unban(self, guild: discord.Guild, user: discord.abc.User):
        await self.service.on_unban(guild.id, user.id)


# ── embeds ────────────────────────────────────────────────────────────────────

def onboarding_embed(guild: discord.Guild, base_url: str) -> discord.Embed:
    e = discord.Embed(color=BRAND, title=f"Thanks for adding me to {guild.name}!",
                      description=("I check new members aren't alts of people you've banned, "
                                   "**without ever storing their IP address.** Setup takes about 2 minutes:"))
    e.add_field(name="1. Run `/setup` in your server", inline=False,
                value="Pick the role verified members get, and a private channel where I'll ask moderators to review.")
    e.add_field(name="2. Lock your channels to verified members", inline=False,
                value=("Server Settings → Roles → **@everyone** → turn off *View Channels*. "
                       "Then turn *View Channels* on for your **Verified** role. Leave one channel "
                       "open to everyone for the Verify button."))
    e.add_field(name="3. Post the Verify button", inline=False,
                value="In `/setup`, press **Post verify message here** in that open channel.")
    e.add_field(name="What I need", inline=False,
                value=("Only *Manage Roles*, *Send Messages*, *Embed Links* and *View Channel*. "
                       "I can't ban or kick anyone: moderators always make that call."))
    e.add_field(name="Privacy", inline=False,
                value=(f"What we store and how deletion works: {base_url}/privacy\n"
                       "Removing me deletes all of this server's data immediately."))
    return e


def welcome_embed(guild: discord.Guild) -> discord.Embed:
    e = discord.Embed(color=BRAND, title=f"Welcome to {guild.name}!",
                      description=("This server asks new members to verify before they can chat. "
                                   "It takes about 10 seconds.\n\n"
                                   "Press **Verify** below. The link is just for you, works once, "
                                   "and expires in 10 minutes. If it expires, press **Send me a new link**."))
    e.set_footer(text="We never store your IP address. Nothing is shared with other servers.")
    return e


def verify_message_embed(guild: discord.Guild, base_url: str) -> discord.Embed:
    e = discord.Embed(color=BRAND, title="Verify to get access",
                      description=("Press **Verify** and open your personal link. You'll see a short "
                                   "explanation, a quick captcha, and then you're in.\n\n"
                                   "Can't use the page, or don't want to? Press **Ask a moderator**."))
    e.add_field(name="Your privacy", value=(
        "• We **never store your IP address**.\n"
        "• Your browser details are turned into codes that can't be turned back.\n"
        "• Nothing is shared with other servers.\n"
        f"• Delete your data any time with **My data**. Details: {base_url}/privacy"), inline=False)
    return e


def case_embed(result) -> discord.Embed:
    e = discord.Embed(color=WARN, title="Verification needs review",
                      description=f"<@{result.user_id}> (`{result.user_id}`)")
    e.add_field(name="Why", value="\n".join(f"• {r}" for r in result.reasons) or "—", inline=False)
    if result.banned_match_user_id:
        e.add_field(name="Matches banned account", inline=False, value=(
            f"<@{result.banned_match_user_id}> (`{result.banned_match_user_id}`), banned "
            f"{fmt_date(result.banned_match_at)}\nMatched on: {', '.join(result.match_reasons)}"))
    net = result.net or {}
    flags = [n for n, k in (("VPN/proxy", "vpn"), ("Tor", "tor"), ("Datacenter", "datacenter")) if net.get(k)]
    if flags:
        e.add_field(name="Network", value=", ".join(flags), inline=False)
    e.set_footer(text="The member only sees “a moderator will review”. They aren't told about any match. "
                      "Shared family computers can match too.")
    return e


def case_view(case_id: str) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(CaseButton("allow", case_id))
    view.add_item(CaseButton("deny", case_id))
    return view


def link_view(url: str, guild_id: int) -> discord.ui.View:
    view = discord.ui.View(timeout=None)
    view.add_item(discord.ui.Button(style=discord.ButtonStyle.link, label="Verify", url=url))
    view.add_item(NewLinkButton(guild_id))
    return view


# ── persistent buttons ────────────────────────────────────────────────────────

class CaseButton(discord.ui.DynamicItem[discord.ui.Button],
                 template=r"case:(?P<action>allow|deny):(?P<cid>[0-9a-f]{24})"):
    def __init__(self, action: str, case_id: str):
        label, style = (("Allow in", discord.ButtonStyle.success) if action == "allow"
                        else ("Keep out", discord.ButtonStyle.secondary))
        super().__init__(discord.ui.Button(label=label, style=style, custom_id=f"case:{action}:{case_id}"))
        self.action = action
        self.case_id = case_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(match["action"], match["cid"])

    async def callback(self, interaction: discord.Interaction):
        bot: VerifyBot = interaction.client
        if not interaction.guild or not isinstance(interaction.user, discord.Member) or not is_mod(interaction.user):
            return await interaction.response.send_message("Only moderators can decide this.", ephemeral=True)
        await interaction.response.defer()
        user_id = await bot.service.resolve_case(interaction.guild.id, self.case_id, self.action)
        if user_id is None:
            return await interaction.followup.send("This case was already decided or has expired.", ephemeral=True)
        note = ""
        if self.action == "allow":
            config = await bot.service.get_config(interaction.guild.id)
            try:
                await bot.http.add_role(interaction.guild.id, user_id, config["verified_role_id"],
                                        reason=f"Allowed by moderator {interaction.user}")
            except discord.HTTPException:
                note = "\n⚠️ I couldn't give the role. Check my role is above it."
        embed = interaction.message.embeds[0] if interaction.message and interaction.message.embeds else discord.Embed()
        embed.color = OK if self.action == "allow" else BAD
        verdict = "Allowed in" if self.action == "allow" else "Kept out"
        embed.add_field(name="Decision", value=f"{verdict} by {interaction.user.mention}{note}", inline=False)
        await interaction.message.edit(embed=embed, view=None)


class NewLinkButton(discord.ui.DynamicItem[discord.ui.Button], template=r"newlink:(?P<gid>\d{15,22})"):
    """Lives in the welcome DM, so it carries the server ID."""

    def __init__(self, guild_id: int):
        super().__init__(discord.ui.Button(label="Send me a new link", style=discord.ButtonStyle.secondary,
                                           custom_id=f"newlink:{guild_id}"))
        self.guild_id = guild_id

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(int(match["gid"]))

    async def callback(self, interaction: discord.Interaction):
        bot: VerifyBot = interaction.client
        guild = bot.get_guild(self.guild_id)
        if guild is None:
            return await interaction.response.send_message("I'm not in that server any more.", ephemeral=True)
        await send_verify_link(interaction, guild)


async def send_verify_link(interaction: discord.Interaction, guild: discord.Guild) -> None:
    bot: VerifyBot = interaction.client
    wait = bot.cooldowns.hit("link", interaction.user.id, 15)
    if wait:
        return await interaction.response.send_message(
            f"Please wait {int(wait) + 1}s before asking for another link.", ephemeral=True)
    config = await bot.service.get_config(guild.id)
    if not Service.is_ready(config):
        return await interaction.response.send_message(
            "Verification isn't set up in this server yet. Ask an admin to run `/setup`.", ephemeral=True)
    try:
        member = guild.get_member(interaction.user.id) or await guild.fetch_member(interaction.user.id)
    except discord.HTTPException:
        return await interaction.response.send_message("You're not in that server.", ephemeral=True)
    if member.get_role(config["verified_role_id"]):
        return await interaction.response.send_message("You're already verified here. ✅", ephemeral=True)
    token = await bot.service.create_session(guild.id, member.id)
    view = discord.ui.View()
    view.add_item(discord.ui.Button(style=discord.ButtonStyle.link, label="Open my verify link",
                                    url=bot.link_for(token)))
    await interaction.response.send_message(
        "Here's your personal link. It works once and expires in 10 minutes. **Don't share it.**",
        view=view, ephemeral=True)


class ManualModal(discord.ui.Modal, title="Ask a moderator to verify you"):
    note = discord.ui.TextInput(label="Anything moderators should know? (optional)",
                                style=discord.TextStyle.paragraph, required=False, max_length=300)

    async def on_submit(self, interaction: discord.Interaction):
        bot: VerifyBot = interaction.client
        config = await bot.service.get_config(interaction.guild.id)
        channel = interaction.guild.get_channel(config["mod_channel_id"] or 0)
        if channel is None:
            return await interaction.response.send_message("Moderators haven't set up a review channel yet.",
                                                           ephemeral=True)
        case_id = await bot.service.create_manual_case(interaction.guild.id, interaction.user.id, str(self.note))
        e = discord.Embed(color=BRAND, title="Manual verification requested",
                          description=f"{interaction.user.mention} (`{interaction.user.id}`) asked a moderator to "
                                      "verify them instead of using the page. No browser checks were run.")
        if str(self.note).strip():
            e.add_field(name="Their note", value=str(self.note)[:300], inline=False)
        await channel.send(embed=e, view=case_view(case_id))
        await interaction.response.send_message("Done: a moderator will look at this soon.", ephemeral=True)


class VerifyMessageView(discord.ui.View):
    """The public message in the verify channel. Persistent across restarts."""

    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify", style=discord.ButtonStyle.success, custom_id="verify:start")
    async def start(self, interaction: discord.Interaction, button: discord.ui.Button):
        await send_verify_link(interaction, interaction.guild)

    @discord.ui.button(label="Ask a moderator", style=discord.ButtonStyle.secondary, custom_id="verify:manual")
    async def manual(self, interaction: discord.Interaction, button: discord.ui.Button):
        bot: VerifyBot = interaction.client
        if bot.cooldowns.hit("manual", interaction.user.id, 600):
            return await interaction.response.send_message(
                "You've already asked recently. A moderator will get to it.", ephemeral=True)
        await interaction.response.send_modal(ManualModal())

    @discord.ui.button(label="My data", style=discord.ButtonStyle.secondary, custom_id="verify:privacy")
    async def privacy(self, interaction: discord.Interaction, button: discord.ui.Button):
        await show_privacy(interaction)


# ── privacy panel (for members) ───────────────────────────────────────────────

STATUS_TEXT = {
    "verified": "verified",
    "pending": "waiting for a moderator",
    "denied": "not let in by a moderator",
    "banned": "**banned** (kept so ban evasion can be caught)",
    "deleting": "deletion requested",
}


async def show_privacy(interaction: discord.Interaction) -> None:
    bot: VerifyBot = interaction.client
    await interaction.response.defer(ephemeral=True, thinking=True)
    rows = await bot.service.user_overview(interaction.user.id)
    e = discord.Embed(color=BRAND, title="Your data")
    e.description = (
        "**What we keep about you, per server:** an encrypted copy of your Discord ID and codes made from your "
        "browser's details (screen, graphics, fonts, time zone…). The codes can't be turned back into those "
        "details, and they're different in every server, so servers can't be linked together.\n"
        "**What we never keep:** your IP address, location, email, or anything from other servers.")
    if rows:
        lines = []
        for r in rows[:20]:
            g = bot.get_guild(r["guild_id"])
            name = g.name if g else "a server I've left"
            lines.append(f"• **{name}**: {STATUS_TEXT.get(r['status'], r['status'])}, deleted by "
                         f"{fmt_date(r['expires_at'])} at the latest")
        e.add_field(name="Servers where we have a record", value="\n".join(lines), inline=False)
    else:
        e.add_field(name="Servers where we have a record", value="None.", inline=False)
    e.add_field(name="About deleting", inline=False, value=(
        "Deleting removes your verified role straight away, and your record stops being used. The rest is "
        "erased within 7 days. If a server bans this account in those 7 days, they keep a ban record, so that "
        "deleting can't be used to dodge a ban.\nBan records can't be deleted by the banned person. They "
        "expire on the server's schedule, or right away if you're unbanned."))
    view = PrivacyView(interaction.user.id) if rows else None
    await interaction.followup.send(embed=e, view=view, ephemeral=True)


class PrivacyView(discord.ui.View):
    def __init__(self, user_id: int):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.armed = False

    @discord.ui.button(label="Delete my data", style=discord.ButtonStyle.danger)
    async def delete(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.user_id:
            return await interaction.response.send_message("This isn't your panel.", ephemeral=True)
        if not self.armed:
            self.armed = True
            button.label = "Yes, delete it (you'll need to verify again)"
            return await interaction.response.edit_message(view=self)
        bot: VerifyBot = interaction.client
        if bot.cooldowns.hit("delete", interaction.user.id, 30):
            return await interaction.response.send_message("Already working on it.", ephemeral=True)
        await interaction.response.defer(ephemeral=True, thinking=True)
        report = await bot.service.delete_user(interaction.user.id)
        for gid in report.deleted_guild_ids:
            config = await bot.service.get_config(gid)
            if config["verified_role_id"]:
                try:
                    await bot.http.remove_role(gid, interaction.user.id, config["verified_role_id"],
                                               reason="Member deleted their verification data")
                except discord.HTTPException:
                    pass
        parts = []
        if report.deleted_guild_ids:
            parts.append(f"✅ Deleted your verification in **{len(report.deleted_guild_ids)}** server(s). "
                         f"Everything left is erased by {fmt_date(report.purge_after)}.")
        if report.already_deleting:
            parts.append(f"Already being deleted in {len(report.already_deleting)} server(s).")
        for gid, until in report.kept_bans:
            g = bot.get_guild(gid)
            parts.append(f"⛔ **{g.name if g else 'A server'}** banned this account, so that record stays "
                         f"until {fmt_date(until)} or until you're unbanned.")
        if not parts:
            parts.append("There was nothing to delete.")
        for child in self.children:
            child.disabled = True
        await interaction.edit_original_response(view=self)
        await interaction.followup.send("\n".join(parts), ephemeral=True)


# ── /setup panel (for admins) ─────────────────────────────────────────────────

class SetupView(discord.ui.View):
    def __init__(self, bot: VerifyBot, guild: discord.Guild, admin_id: int, config: dict):
        super().__init__(timeout=900)
        self.bot = bot
        self.guild = guild
        self.admin_id = admin_id
        self.config = config
        self.confirm_delete = False
        self.vpn.options = [discord.SelectOption(label=VPN_LABELS[k], value=k, default=config["vpn_policy"] == k)
                            for k in ("allow", "review", "block")]
        self.ban_days.options = [discord.SelectOption(
            label=f"Keep ban records {d} days", value=str(d), default=config["ban_days"] == d,
            description="How long a banned account's record is kept to catch its alts")
            for d in BAN_DAY_CHOICES]
        self.toggle_dm.label = f"Welcome DM: {'on' if config['dm_on_join'] else 'off'}"
        self.toggle_alts.label = f"Alt notices: {'on' if config['alt_notices'] else 'off'}"

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.admin_id:
            await interaction.response.send_message("Run `/setup` yourself to change settings.", ephemeral=True)
            return False
        return True

    async def embed(self) -> discord.Embed:
        c = self.config
        me = self.guild.me
        role = self.guild.get_role(c["verified_role_id"] or 0)
        mod = self.guild.get_channel(c["mod_channel_id"] or 0)
        verify_ch = self.guild.get_channel(c["verify_channel_id"] or 0)
        role_issue = role_problem(role, me) if role else None
        mod_issue = channel_problem(mod, me) if mod else None

        def line(ok: bool, text: str) -> str:
            return ("✅ " if ok else "⬜ ") + text

        e = discord.Embed(color=BRAND, title="Verification setup")
        e.add_field(name="Checklist", inline=False, value="\n".join([
            line(bool(role) and not role_issue, f"Verified role: {role.mention if role else 'not set'}"
                 + (f"\n  ⚠️ {role_issue}" if role_issue else "")),
            line(bool(mod) and not mod_issue, f"Moderator review channel: {mod.mention if mod else 'not set'}"
                 + (f"\n  ⚠️ {mod_issue}" if mod_issue else "")),
            line(bool(verify_ch), f"Verify message: {verify_ch.mention if verify_ch else 'not posted yet'}"),
            line(not self.guild.default_role.permissions.view_channel,
                 "@everyone can't see channels (Server Settings → Roles → @everyone → View Channels off)"),
        ]))
        e.add_field(name="Settings", inline=False, value=(
            f"**VPNs:** {VPN_LABELS[c['vpn_policy']]}\n"
            f"**Ban records kept:** {c['ban_days']} days after a ban (deleted right away on unban)\n"
            f"**Welcome DM with link:** {'on' if c['dm_on_join'] else 'off'}\n"
            f"**Alt notices** (when a new member shares a device with a current member): "
            f"{'on' if c['alt_notices'] else 'off'}"))
        stats = await self.bot.service.stats(self.guild.id)
        e.add_field(name="Records", inline=False, value=(
            f"{stats['verified']} verified · {stats['pending']} waiting · {stats['banned']} ban records · "
            f"{stats['open_cases']} open cases"))
        e.set_footer(text="Matches never ban anyone automatically: moderators decide. We never store IP addresses.")
        return e

    async def refresh(self, interaction: discord.Interaction, notice: Optional[str] = None):
        self.config = await self.bot.service.get_config(self.guild.id)
        fresh = SetupView(self.bot, self.guild, self.admin_id, self.config)
        embed = await fresh.embed()
        if notice:
            embed.description = notice
        await interaction.response.edit_message(embed=embed, view=fresh)
        self.stop()

    @discord.ui.select(cls=discord.ui.RoleSelect, placeholder="Role to give verified members", row=0)
    async def role(self, interaction: discord.Interaction, select: discord.ui.RoleSelect):
        role = select.values[0]
        problem = role_problem(role, self.guild.me)
        if problem:
            return await self.refresh(interaction, f"⚠️ {problem}")
        await self.bot.service.update_config(self.guild.id, verified_role_id=role.id)
        await self.refresh(interaction, f"Verified members will get {role.mention}.")

    @discord.ui.select(cls=discord.ui.ChannelSelect, channel_types=[discord.ChannelType.text],
                       placeholder="Private channel for moderator reviews", row=1)
    async def mod_channel(self, interaction: discord.Interaction, select: discord.ui.ChannelSelect):
        channel = self.guild.get_channel(select.values[0].id)
        problem = channel_problem(channel, self.guild.me) if channel else "I can't see that channel."
        if problem:
            return await self.refresh(interaction, f"⚠️ {problem}")
        if channel.permissions_for(self.guild.default_role).view_channel:
            note = f"⚠️ {channel.mention} is visible to everyone. Reviews name members, so make it moderators-only."
        else:
            note = f"Reviews will go to {channel.mention}."
        await self.bot.service.update_config(self.guild.id, mod_channel_id=channel.id)
        await self.refresh(interaction, note)

    @discord.ui.select(placeholder="VPN policy", row=2)
    async def vpn(self, interaction: discord.Interaction, select: discord.ui.Select):
        await self.bot.service.update_config(self.guild.id, vpn_policy=select.values[0])
        await self.refresh(interaction, f"VPN policy: {VPN_LABELS[select.values[0]]}.")

    @discord.ui.select(placeholder="Ban record retention", row=3)
    async def ban_days(self, interaction: discord.Interaction, select: discord.ui.Select):
        await self.bot.service.update_config(self.guild.id, ban_days=int(select.values[0]))
        await self.refresh(interaction, f"New ban records are kept {select.values[0]} days.")

    @discord.ui.button(label="Post verify message here", style=discord.ButtonStyle.success, row=4)
    async def post(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not Service.is_ready(self.config):
            return await self.refresh(interaction, "⚠️ Pick the verified role and the review channel first.")
        channel = interaction.channel
        problem = channel_problem(channel, self.guild.me) if isinstance(channel, discord.TextChannel) else \
            "Run this in a normal text channel."
        if problem:
            return await self.refresh(interaction, f"⚠️ {problem}")
        await channel.send(embed=verify_message_embed(self.guild, self.bot.settings.public_base_url),
                           view=VerifyMessageView())
        await self.bot.service.update_config(self.guild.id, verify_channel_id=channel.id)
        await self.refresh(interaction, f"Posted the verify message in {channel.mention}. Make sure everyone "
                                        "can see this channel, but not the rest of the server.")

    @discord.ui.button(label="Welcome DM", style=discord.ButtonStyle.secondary, row=4)
    async def toggle_dm(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.bot.service.update_config(self.guild.id, dm_on_join=not self.config["dm_on_join"])
        await self.refresh(interaction)

    @discord.ui.button(label="Alt notices", style=discord.ButtonStyle.secondary, row=4)
    async def toggle_alts(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.bot.service.update_config(self.guild.id, alt_notices=not self.config["alt_notices"])
        await self.refresh(interaction)

    @discord.ui.button(label="Delete all server data", style=discord.ButtonStyle.danger, row=4)
    async def delete_all(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self.confirm_delete:
            self.confirm_delete = True
            button.label = "Really delete everything? Press again"
            return await interaction.response.edit_message(view=self)
        counts = await self.bot.service.shred_guild(self.guild.id)
        await interaction.response.edit_message(embed=discord.Embed(
            color=BAD, title="All data deleted",
            description=(f"Deleted this server's encryption key, settings and {counts['records']} records, "
                         "including ban records. Existing verified roles were left alone. "
                         "Run `/setup` to start again.")), view=None)
        self.stop()


# ── slash commands ────────────────────────────────────────────────────────────

def register_commands(bot: VerifyBot) -> None:
    tree = bot.tree

    @tree.command(name="setup", description="Set up verification for this server (admins)")
    @app_commands.guild_only()
    @app_commands.default_permissions(manage_guild=True)
    async def setup_cmd(interaction: discord.Interaction):
        if not interaction.user.guild_permissions.manage_guild:
            return await interaction.response.send_message("You need Manage Server to do this.", ephemeral=True)
        config = await bot.service.get_config(interaction.guild.id)
        view = SetupView(bot, interaction.guild, interaction.user.id, config)
        await interaction.response.send_message(embed=await view.embed(), view=view, ephemeral=True)

    @tree.command(name="verify", description="Get a verification link for this server")
    @app_commands.guild_only()
    async def verify_cmd(interaction: discord.Interaction):
        await send_verify_link(interaction, interaction.guild)

    @tree.command(name="privacy", description="See or delete the data this bot keeps about you")
    async def privacy_cmd(interaction: discord.Interaction):
        await show_privacy(interaction)

    @tree.command(name="invite", description="Add this bot to another server")
    async def invite_cmd(interaction: discord.Interaction):
        url = discord.utils.oauth_url(bot.application_id, permissions=discord.Permissions(INVITE_PERMISSIONS),
                                      scopes=("bot", "applications.commands"))
        await interaction.response.send_message(f"[Add me to your server]({url})", ephemeral=True)


# ── entry point ───────────────────────────────────────────────────────────────

def setup_logging() -> None:
    # Console only; never log user IDs, IPs or signals. Errors are logged with
    # server IDs at most.
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("discord.http").setLevel(logging.WARNING)


def main() -> None:
    load_dotenv()
    setup_logging()
    try:
        settings = BotSettings.from_env()
    except ConfigError as exc:
        sys.exit(f"Config error: {exc}")
    mongo = AsyncIOMotorClient(settings.mongo_uri, tz_aware=True)
    service = Service(mongo[settings.db_name], settings.keyring, settings.job_private_key, settings.retention)
    VerifyBot(settings, service).run(settings.discord_token, log_handler=None)


if __name__ == "__main__":
    main()
