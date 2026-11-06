# SyntaxHQ verification bot: research and plan

*Working name: "the verification bot" (no name chosen yet). Status: plan only, no code. Date: 6 November 2026.*

---

## 0. How this was researched, and what to trust

- **The sources are search results, not pages read in full.** This cloud session's network blocks direct page fetches to doublecounter.gg, docs.doublecounter.gg, top.gg, support-dev.discord.com, edpb.europa.eu, ico.org.uk, brave.com and the competitor sites (DNS failures). So every claim below comes from web-search summaries, with the source linked. Before launch, re-read the primary pages yourself, especially the **Discord Developer Policy** (I could not get its current text), Double Counter's privacy policy and incident report, and the EDPB/ICO guidance.
- **[Unverified]** marks claims I could not confirm from at least one source that cites the primary document.
- **[Own knowledge]** marks technical points from general engineering knowledge rather than a 2026 source. They are still worth checking.
- **[Lawyer]** marks a question that needs real legal advice. Nothing here is legal advice.

### Corrections to the brief

| Your brief said | What I found |
|---|---|
| 600,000+ servers | Matches: reports describe it as guarding "600,000+ communities" ([IntCyberDigest](https://x.com/IntCyberDigest/status/2116922462592241982), [egamers](https://egamers.io/discord-blocks-new-installs-of-double-counter-after-hacker-hijacks-the-security-bot/)). Its own Doogle docs claim "500,000 Discord servers and 40+ million users" ([DC docs](https://docs.doublecounter.gg/double-counter-en/doogle)). |
| top.gg rating ~2.69, over half 1-star | 2.69 from **198 reviews** is confirmed. "Over half 1-star" is **unverified**: one top.gg snapshot shows 105 one-star reviews, but that snapshot doesn't line up with the 198 total ([top.gg](https://top.gg/bot/703886990948565003)). |
| Keeps data up to 24 months | The policy dated 29 Oct 2025 said IPs are stored encrypted and kept "up to 24 months from the most recent detection or verification attempt" ([Peakbot](https://peakbot.pro/blog/is-double-counter-safe)). One analysis says the **retention section was removed from the policy shortly after the breach** ([ipregistry](https://ipregistry.co/blog/double-counter-breach-ip-address-retention)). Another says an earlier version had no expiry at all ([lina.sh](https://lina.sh/-dcounter)). Also, DC's docs say **alt detections are permanent and cannot be edited** ([DC docs](https://docs.doublecounter.gg/double-counter-en/alt-detections-and-vpn-intrusions)). |
| ~1M emails exposed | That is the early figure. **Have I Been Pwned counted 274,922 unique emails** in the dataset that was later published ([HIBP](https://haveibeenpwned.com/Breach/DoubleCounter), [DigitalCitizen](https://www.digitalcitizen.life/double-counter-discord-bot-breach-275000-emails/)). The operator treats **~28M accounts** as exposed, including IP and rough location for **~27M** ([tech-insider](https://tech-insider.org/double-counter-discord-breach-28-million-accounts-2026/), [Outlook Respawn](https://respawn.outlookindia.com/gaming/gaming-news/double-counter-discord-breach-exposes-millions-of-user-records)). |
| Discord disabled new installs on 12 Oct | Discord did disable new installs while it investigated, and existing installs keep working ([egamers](https://egamers.io/discord-blocks-new-installs-of-double-counter-after-hacker-hijacks-the-security-bot/), [techjournal](https://techjournal.org/discord-double-counter-breach)). **The exact date is unverified**, and so is whether installs have been re-enabled since. Check before you rely on it in marketing. |
| Missing from your brief | The attacker also misused a Stripe key for a sister product (Atis): about **$7,331 in fraudulent charges** ([Outlook Respawn](https://respawn.outlookindia.com/gaming/gaming-news/double-counter-discord-breach-exposes-millions-of-user-records)). |
| Missing from your brief | **Double Counter now markets itself as "privacy-first"**, with "privacy-preserving device fingerprinting", "EU hosting", deletion endpoints and a server-local mode ([doublecounter.gg](https://doublecounter.gg/), [features](https://doublecounter.gg/features)). The word "privacy" alone will not set us apart. See §1. |

---

## Phase 1: Research

### 1.1 How Double Counter works

- **Verification:** the user clicks a link, then browser checks run. No Discord login, no app to authorise, no captcha on the main flow. Raid protection is described separately as an "invisible house-made captcha" plus pattern recognition ([doublecounter.gg](https://doublecounter.gg/discord-verification-bot), [FAQ](https://doublecounter.gg/faq)).
- **Signals:** the IP address is the main signal. User-agents are kept "for manual inspection in case of alt-flagging dispute". Cookies, "other algorithmic data", and device and browser signals fused into "a cross-account identity" ([privacy policy](https://docs.doublecounter.gg/double-counter-en/legal), [alt docs](https://docs.doublecounter.gg/double-counter-en/alt-detections-and-vpn-intrusions), [doublecounter.gg](https://doublecounter.gg/)). Its docs say an account is flagged when the user "shares an IP with them, used their verification link, or used the same device".
- **VPN/proxy/Tor:** blocks "VPNs, datacenter IPs, Tor relays, and virtual machines in real time", with "IP data refreshed hourly". VPN intrusions are per-server and not permanent ([features](https://doublecounter.gg/features)).
- **Cross-server:** admins choose between a shared network and server-local checks ([features](https://doublecounter.gg/features)).
- **Pricing:** "free forever for the vast majority of communities". Pro is billed through Discord and adds ad-free verification, custom embeds and timeouts, "DC Fingerprinting analytics", cross-database checks and right-click actions. **I found no price** ([FAQ](https://doublecounter.gg/faq)).
- **Doogle:** a slash command (`/doogle @user`) that lists "known associated Discord accounts that may be operated by the same individual", across their whole network, **including servers that don't use Double Counter**. Sources disagree on access: included in Pro, or freemium with paid tiers ([DC docs](https://docs.doublecounter.gg/double-counter-en/doogle), [tellter](https://tellter.com/projects/doogle), [doublecounter.gg](https://doublecounter.gg/doogle-the-ultimate-discord-alt-account-detection-tool)). Critics call it "a glorified doxing tool" ([lina.sh](https://lina.sh/-dcounter)).
- **Deletion:** `/privacy` command with a 30-day response window. According to Peakbot, only the IP is deleted on request and other non-PII data stays ([Peakbot](https://peakbot.pro/blog/is-double-counter-safe)).
- **Disputes:** "The choice to allow an alt account into a server is entirely up to the staff team"; staff can bypass the check with `/manverify` ([alt docs](https://docs.doublecounter.gg/double-counter-en/alt-detections-and-vpn-intrusions)).

### 1.2 The breach, and what it means for our design

| When (4 Oct 2026, UTC) | What happened |
|---|---|
| 00:47 | The attacker forged an admin session on a **self-hosted Metabase** (analytics tool) running on a **retired server from DC's "previous OVH hosting setup"**. The server was still publicly reachable but no longer linked to the live service ([rocket-boys](https://rocket-boys.co.jp/?p=43025), [Pirat_Nation](https://x.com/Pirat_Nation/status/2107796290461466941)). |
| next ~6h | They used **cloud credentials found on that box** to get cloud admin access and the **bot token**. They stayed in the cloud for 5h51m. |
| 15:09–15:34 | Data copied out. |
| same day | The bot token was used to post invite spam in **~50 large servers**. A Stripe key for a sister product was misused (~$7.3k fraud). |
| 19:19 | Service restored. |
| 5 Oct | Public incident report. **CNIL** (French regulator) notified. Credentials revoked, bot token and webhooks reset, 14 cloud projects audited, secret-access monitoring added. Criminal complaints filed in France and the US ([Outlook Respawn](https://respawn.outlookindia.com/gaming/gaming-news/double-counter-discord-breach-exposes-millions-of-user-records), [gblock](https://www.gblock.app/articles/double-counter-discord-bot-breach-28-million-2026)). |
| later | Data published. HIBP: 274,922 emails plus usernames ([HIBP](https://haveibeenpwned.com/Breach/DoubleCounter)). Discord disabled new installs and said "this was not a breach of Discord". |

**Lessons we build in:**
1. **Forgotten infrastructure kills.** Keep an infrastructure inventory. Every machine gets a decommission checklist. No self-hosted admin or analytics tool is ever reachable from the internet.
2. **One leaked secret should not open everything.** No long-lived cloud keys on servers. The bot token, database credentials, payment keys and encryption keys are all separate, scoped and monitored.
3. **Stored IPs were the payload.** If we never store IPs, an IP leak is impossible, not merely unlikely.
4. **The bot token is a weapon.** Request minimal permissions so a stolen token can't ban, kick or post anywhere (§7.6).
5. **Sister products share blast radius.** Keep PinPal's and this bot's secrets, databases and accounts fully separate.

### 1.3 Competitors

| Bot | Detection | Data | Retention | Price | Size / rating | Main weakness |
|---|---|---|---|---|---|---|
| **Double Counter** | IP, cookies, device and browser signals; VPN/Tor/VM blocking | IP (encrypted), UA, Discord ID/username | Up to 24 mo, policy now unclear | Free; Pro via Discord, price not found | 600k+ servers; 2.69★ / 198 | Breach, new installs blocked, IP retention, Doogle, permanent flags, household false positives |
| **Verification** (top.gg, 46.2K servers, 4.67★, per the earlier chat) | IP, cookie and fingerprint comparison; VPN/VM and country blocking ([search](https://top.gg/ko/bot/1011135011413577768)) | Same class as DC | **Unverified** | **Unverified** | 46.2K, 4.67★ (from the earlier chat, not re-verified) | Same IP-collection model as DC, so the same breach risk |
| **AuthenticateMe** | Anti-alt (free); "Fingerprint Detection" and "Block Privacy Focused Settings" (premium); VPN/proxy and incognito blocking ([docs](https://docs.authenticateme.xyz/en/owners-manual)) | **Unverified**: couldn't read its data page | **Unverified** | Free plus premium | **Unverified** | Pitches privacy, yet **sells blocking privacy browsers and incognito as a premium feature**. It also lists the same top.gg ID (1011135011413577768) as the "Verification" result above, so **these may be the same bot. Check.** |
| **Wick** | Anti-raid/anti-nuke; alt detection from account age, creation patterns, behaviour ([Peakbot](https://peakbot.pro/blog/wick-vs-vaultcord-2026), a competitor's blog) | Discord-side only | n/a | Free plus premium | Large | Weak at real alt detection |
| **VaultCord** | Captcha plus **OAuth2** (gets more account data) ([Peakbot](https://peakbot.pro/blog/wick-vs-vaultcord-2026)) | OAuth2 scopes, possibly email/guilds. **Unverified** | **Unverified** | **Unverified** | **Unverified** | OAuth2 asks for more than verification needs |
| **RestoreCord** | OAuth2 member backup and restore | OAuth tokens | **Unverified** | **Unverified** | **Unverified** | Holding OAuth tokens is a juicy target |
| **Verifeon** | VPN/proxy/datacenter checks; alt detection on the free plan; premium billed monthly per server ([top.gg](https://top.gg/cs/bot/1542559582990110790)) | **Unverified** | **Unverified** | Free plus monthly | **Unverified** | **Unverified** |
| **Captcha.bot** | Captcha only | Minimal | n/a | **Unverified** | **Unverified** | No alt detection |
| **Beemo** | Userbot-raid detection; free with "Beemo Max" premium; open-source code ([docs](https://github.com/beemobot/docs.beemo.gg/blob/main/index.md)) | Discord-side | n/a | Free / Max | Large | Not an alt detector; a complement, not a rival |
| **BetterAntispam, PeakBot** | Publish "vs Double Counter" pages ([BetterAntispam](https://betterantispam.com/en/blog/betterantispam-vs-double-counter)) | **Unverified** | | | | Both write SEO comparison content, so expect a crowded search page |

### 1.4 What users and admins complain about (themes)

1. **Household, roommate and sibling false positives.** DC's own docs confirm that sharing an IP is enough to flag ([alt docs](https://docs.doublecounter.gg/double-counter-en/alt-detections-and-vpn-intrusions)). Third-party guides list "siblings, roommates or partners verifying from the same home connection" as a top cause ([Peakbot](https://peakbot.pro/blog/is-double-counter-safe)).
2. **CGNAT and shared ISP IPs.** Strangers on the same carrier share a public IP, so one person's ban spreads to others ([lokamc forum](https://forums.lokamc.com/threads/traqsoul-unban-appeal.10477/latest), [Nextcloud CGNAT explainer](https://help.nextcloud.com/t/what-cg-nat-is-how-to-detect-it-why-it-is-bad-what-can-you-do-about-it/201908)).
3. **Permanent, uneditable flags**, and support that says it won't override server decisions ([alt docs](https://docs.doublecounter.gg/double-counter-en/alt-detections-and-vpn-intrusions)).
4. **Privacy and doxing concerns**: Doogle, and a reported case of revealing a household member through a shared IP ([lina.sh](https://lina.sh/-dcounter)).
5. **VPN users blocked**, with an appeal only through a support ticket.
6. I could not read individual top.gg reviews or Reddit threads (blocked), so **theme frequencies are unverified**.

### 1.5 Rules

- **Discord Developer Terms (current):** §5(a) requires a privacy policy that explains how users request deletion. §5(b) requires deleting API data when no longer needed, on user request, or on Discord's request, plus an easy way to request changes or deletion. §9(b) requires deleting data on termination ([Developer Terms](https://support-dev.discord.com/hc/en-us/articles/8562894815383-Discord-Developer-Terms-of-Service), via search summary).
- **Discord Developer Policy:** I could **not** read the current text. The 2022 version bans scraping, using data against user expectations, contacting users off-Discord without consent, and helping anyone "bypass or circumvent Discord's privacy, safety, and security measures" ([2022 policy](https://support-dev.discord.com/hc/en-us/articles/25280499088279-2022-Discord-Developer-Policy)). The 2017 terms banned selling end-user data. **Read the current policy before building.** A cross-server people search like Doogle is the kind of feature most likely to clash with it.
- **ePrivacy Art. 5(3) (EU):** the EDPB Guidelines 2/2023 (v2, adopted 7 Oct 2024) say fingerprinting is within scope, whether or not the data is personal. Reading device info through JavaScript counts as "access" ([EDPB](https://www.edpb.europa.eu/documents/530_en), [Hunton](https://hunton.com/privacy-and-information-security-law/edpb-publishes-guidelines-to-clarify-scope-of-eu-cookie-notice-and-consent-requirements)). So we need **consent** unless the "strictly necessary for a service explicitly requested by the user" exemption applies. Whether a server-*required* check counts as "explicitly requested by the user" is unclear. **[Lawyer]**
- **UK (ICO/PECR):** fingerprinting needs consent by default. "Preventing or detecting fraud" and "security" are listed as likely to qualify for the strictly-necessary exemption, but third-party fingerprinting for fraud is also used as an example that *does* need consent. The exemption does not cover secondary uses such as inferences about people. Final guidance came in April 2026, and I didn't read its text ([DLA Piper](https://privacymatters.dlapiper.com/2025/01/googles-u-turn-on-device-fingerprinting-icos-response-and-subsequent-guidance/), [Mondaq](https://www.mondaq.com/uk/privacy-protection/1794984/ico-cookie-crackdown-20-the-icos-new-storage-and-access-technologies-guidance)).
- **GDPR:** **keyed hashes (HMACs) are pseudonymised data, so they are still personal data** while anyone holds the key (EDPB Guidelines 01/2025 on pseudonymisation; [Stibbe](https://stibbe.com/publications-and-insights/key-takeaways-and-insights-from-the-edpb-pseudonymisation-guidelines)). So GDPR fully applies: lawful basis (likely legitimate interests, with fraud prevention per Recital 47 [own knowledge]), privacy notice, user rights, 72-hour breach notification (Art. 33) [own knowledge]. The real benefit of pseudonymisation is **lower risk and harm in a breach**, not escaping the law.
- **Controller or processor?** The server owner chooses to use the bot, but SyntaxHQ designs the processing. We are probably a controller, or joint controller. **[Lawyer]**
- **Australia:** the Privacy Act's small-business exemption (under A$3M turnover) may still apply to SyntaxHQ, but its removal is under review [own knowledge, unverified status]. The **statutory tort for serious invasions of privacy has applied since 10 June 2025**. The **Children's Online Privacy Code** must be registered by **10 Dec 2026** and will cover services likely to be used by children, which includes Discord bots ([MinterEllison](https://www.minterellison.com/articles/privacy-and-other-legislation-amendment-act-2024-now-in-effect), [Mondaq](https://www.mondaq.com/australia/privacy-protection/1640630/australias-ongoing-privacy-reforms-bolstering-australias-privacy-regulatory-framework)). **[Lawyer]**
- **CCPA/CPRA:** probably doesn't apply to a small solo business, since it applies above revenue or volume thresholds [own knowledge; thresholds unverified for 2026]. Design as if it did anyway: no selling or sharing of data.
- **Children:** Discord allows users from age 13. Fingerprinting minors raises the bar under the UK Children's Code and the coming AU code. One more reason to collect less. **[Lawyer]**

### 1.6 Technical options for one-way matching

- **Keyed hashing (HMAC-SHA-256) per signal**, not one hash of the whole fingerprint. Fingerprints drift with updates (FP-Stalker: changes "every few hours to days", yet linkable for 51.8 days on average; [survey](https://arxiv.org/pdf/1905.01051), [FP-Stalker](https://hal.archives-ouvertes.fr/hal-01652021)). Hashing each component separately lets us count how many components match.
- **The honest limit of "one-way":** a keyed hash is only one-way while the key is secret. Low-entropy inputs can be brute-forced once the key leaks. An IPv4 address has 2³² possible values, which takes seconds to try; a time zone has a few hundred. So **where the key lives is the whole design** (§4.2).
- **Per-server keys** make cross-server linking impossible, even for us, and make crypto-shredding a server's data a single key delete.
- **Stability gaps:** Brave adds per-site, per-session noise to canvas, audio and WebGL ("farbling"), though forum posts say some libraries can undo it ([Brave community](https://community.brave.com/t/fingerprinting-how-do-we-know-its-actually-working/134536)). Firefox's resistFingerprinting returns generic values. Safari private browsing adds fingerprinting protection [own knowledge, unverified details]. **Identical iPhones** (same model and iOS) produce near-identical canvas and WebGL output [own knowledge; I found no measurement]. Mobile fingerprints are much less unique than desktop ones ("Hiding in the Crowd", [survey](https://arxiv.org/pdf/1905.01051)).
- **On-the-spot VPN/datacenter checks** without storing the IP: a local, offline ASN or datacenter database plus the Tor exit list, looked up in memory. We keep only the yes/no result. Candidate data sources: an offline ASN database (e.g. IPinfo Lite, DB-IP or GeoLite2 ASN) and public VPN/datacenter range lists. **[Unverified]**: check each licence and its accuracy.
- **A first-party device token** (a random value in localStorage/IndexedDB on our verify domain) is the cheapest strong signal for "same browser, new account". It is also "storage on the device", so it falls under the same consent analysis.

---

## Phase 2: The plan

### What I found in PinPal (read-only; nothing in that repo was changed)

| Area | Finding | Reuse? |
|---|---|---|
| Stack | Python, `discord.py>=2.7.1` `AutoShardedBot`, MongoDB via `motor`, `python-dotenv`, `aiohttp` (`r.txt`) | **Yes.** Same language and libraries, so you maintain one way of doing things. |
| Intents | `Intents.none()` plus guilds and guild_messages only, `chunk_guilds_at_startup=False` | **Yes.** The same minimal approach. |
| Setup UI | `discord.ui.View`/`Modal` panels (`ServerPanel`, `ConfirmPrompt`, many modals) | **Yes.** Copy the pattern for `/setup`. |
| Billing | `polar.py`: Polar **polled outbound**, no webhook or open port, product IDs per plan | **Yes.** Same Polar account, new products. The "no inbound port" principle is good; keep it for the bot process. |
| Deletion | Server panel "delete pins / presets / all"; retention purges (activity 90d, events/snapshots 400d); pins of removed servers kept 30 days then purged | **Pattern yes, numbers no.** For this bot, removal means an immediate crypto-shred, not a 30-day holding period. |
| Owner tools | In-Discord **DB editor** (`DBEditFieldModal`, custom search), `/plusadmin`, gated by `is_owner()` plus an 8-digit TOTP; `OWNER_ID` hard-coded | **No.** An in-chat database editor is exactly the "admin tool reachable from outside" the DC breach used. The new bot gets aggregate counts only, with no record browser. |
| Logging | `sticky_messages.log` and `backup_logs/` are **committed to git** and contain server names and channel/guild IDs; `.DS_Store` and `__pycache__` are committed too | **No.** In the new bot, logs never contain user IDs or signals, and log files are never committed. (Worth tidying in PinPal separately. I didn't touch it.) |
| Structure | `main.py` is ~446 KB in one file; pure helpers live in `pinkit.py` with tests (`tests/`, about 110 test functions, `mongomock-motor`) | Copy the **testing approach**, but split the new bot into modules from day one. The security-critical code (hashing, matching, deletion) must be small and reviewable. |
| Hosting | No deploy or infrastructure files in the repo | **Unknown.** Tell me where PinPal runs. Note this bot **needs a public HTTPS endpoint** (the verify page), which PinPal deliberately avoids. That is the biggest new risk and the biggest maintenance cost. |

### 1. Summary and positioning

**One line:** *Alt detection that cannot leak your IP, because it never keeps it.*

Why servers would switch:
- New servers **can't install Double Counter** while installs are disabled (check this is still true at launch).
- Admins and members who read about the breach now care what a verification bot stores.
- The PinPal brand: 6,500+ servers already trust SyntaxHQ, and the PinPal-style visual setup is easy.

How we beat the others with **verifiable** claims rather than adjectives, since DC also says "privacy-first":

| Claim | DC | AuthenticateMe / Verification | Us |
|---|---|---|---|
| Stores IP addresses | Yes, encrypted, up to 24 mo | Unverified (Verification: IP-based) | **Never.** Checked in memory, then discarded. |
| Cross-server network / people search | Optional network plus Doogle | AuthenticateMe: per-server | **Impossible by design** (per-server keys). We can't add it without a public re-key. |
| Flags expire | Permanent | Unverified | **Yes.** They expire, and moderators can clear them. |
| Punishes privacy browsers or incognito | VPN blocking | **Sold as a premium feature** | **No by default.** Low-confidence results go to moderator review, never automatic blocking. |
| Bot can ban or kick if its token is stolen | Unverified | Unverified | **No.** It doesn't ask for those permissions (§7.6). |
| Verify page code public | No | Unverified | **Yes**: the verify page and the hashing code are open source. |
| Accuracy | Higher (IP plus network) | Similar to DC | **Lower. Say so.** We catch lazy and careless alts and miss determined ones. |

### 2. Scope

**v1 does:**
- A Verify button, then a link to our web page: consent, captcha, browser checks. The verified role is granted.
- Per-server matching of new verifications against (a) members this server **banned** and (b) other accounts that verified in this server.
- On-the-spot VPN, datacenter and Tor checks. Each server picks Allow, Review or Block (default: **Review**).
- A moderator review queue, an appeal form, and expiring flags.
- Manual verification by moderators, for people who refuse consent or can't use the page.
- User self-delete, server delete, automatic retention, and crypto-shredding on removal.
- PinPal-style `/setup` panel, and Polar billing for Plus.

**v1 explicitly does NOT do:**
- Any cross-server network, shared ban list, or people search ("Doogle").
- Storing raw IPs, IP-derived location, ISP/ASN, email, or the full user-agent.
- Discord OAuth2. It isn't needed, and it would bring email, guild lists and token storage.
- Automatic bans or kicks. The bot doesn't have those permissions.
- Blocking privacy browsers or incognito.
- Importing Double Counter data, which isn't possible and which we wouldn't want anyway.
- Analytics dashboards on individual records (no Metabase-style tools, ever).

### 3. Verification flow

1. **Server setup:** admin runs `/setup`. Panel steps: pick the verified role, the verify channel, the mod-review channel, the VPN policy and the retention length. The bot posts a "Verify" message with a button.
2. **Click Verify:** the bot replies ephemerally with a one-time link `https://verify.<domain>/v/<token>`. The token is a signed claim `{guild_id, user_id, nonce, exp=10min}`, single use. No Discord login is needed, because the token proves who clicked.
3. **Consent screen** (before any script reads the device). Plain language, about 80 words:
   > *"To stop banned people coming back on new accounts, this server checks whether your browser looks like one used by another account **in this server**. We read some technical details of your browser (like screen size and graphics card), turn them into codes that can't be turned back, and keep only the codes, for up to N days. We check whether you're on a VPN, but **we never save your IP address**. Nothing is shared with other servers. [Full details] — [Continue] [No thanks — ask a moderator instead]"*
   - "No thanks" sends a manual-verification request to the mod queue. Because there is a real alternative, the consent is freely given rather than "agree or you can't join" (GDPR Art. 7(4) logic). **[Lawyer]**
4. **Captcha:** self-hosted proof-of-work (e.g. ALTCHA, open source) by default, so no third party sees the user. Cloudflare Turnstile is the fallback option if bots get through, but it involves a third party. **Decision for you.**
5. **Collect** (JavaScript, ~1 second): signals listed in §4.1, plus the first-party device token (created if missing).
6. **Submit** over HTTPS. The web tier (§7.2):
   - looks up the client IP in the offline ASN, datacenter and Tor lists, in memory, and keeps `{vpn: bool, datacenter: bool, tor: bool}`
   - optionally computes `ip_prefix_mac = KMS-MAC(/24 or /64 prefix)` (see Decision 2)
   - **drops the IP** (it is never written to logs; see §7.7)
   - seals the raw signals to the bot's public key (libsodium sealed box) and queues the job.
7. **Matcher** (bot process, no inbound ports): unseals, computes per-server HMACs, discards the raw signals, matches, decides.
8. **Outcome:**
   - *Clear*: role granted. The page says "You're verified, you can close this tab."
   - *Review*: the page says "A moderator will check your verification shortly." No reason given, nobody named. The case goes to the mod queue.
   - *Blocked (VPN policy = Block)*: "This server doesn't allow VPNs during verification. Turn it off and try again, or ask a moderator."

### 4. Detection design

#### 4.1 Signals

| Signal | Entropy | Stability | Notes |
|---|---|---|---|
| First-party device token | Very high | Until storage is cleared | Strongest signal for the same browser. Absent in incognito. |
| Canvas render hash | High | Medium | Noised by Brave and Safari private browsing. |
| WebGL vendor/renderer plus parameter hash | Med–High | High | Near-identical on the same iPhone model. |
| Audio context hash | Medium | Medium | Noised by Brave. |
| Installed font hash (probe list) | Med–High (desktop) | Medium | Low on mobile. |
| Screen size, colour depth, pixel ratio | Low | High | |
| Time zone, languages | Low | High | |
| Platform, hardware concurrency, device memory | Low | High | |
| UA *family and major version* only | Low | Low (updates) | We store the family, not the full UA. |
| IP prefix MAC (optional) | Low (brute-forceable) | Low (mobile, CGNAT) | **Never enough on its own.** See Decision 2. |

We don't collect: geolocation, battery, Bluetooth, media device lists, clipboard, or anything needing a permission prompt.

#### 4.2 Hashing and keys (the core of the pitch)

```
For each signal s in a verification for guild g:
    inner_s = HMAC(K_global, s)              # K_global held in the matcher's secret store
                                             # (for the IP prefix: KMS GenerateMac, key never leaves KMS)
    stored_s = HMAC(K_g, "sig:" + name + ":" + inner_s)
User lookup key:  uid_tag = HMAC(K_g, "uid:" + user_id)
User ID itself:   user_id_ct = AES-256-GCM(K_g, user_id)
K_g: 256-bit random per guild, stored only wrapped: wrap(K_g) = KMS.Encrypt(K_master, K_g)
```

- **A database dump alone** shows opaque bytes: no IPs, no Discord IDs, no way to tell which server's rows link to which.
- **Database plus wrapped keys** shows nothing more, because unwrapping needs KMS.
- **Database plus KMS access** (full matcher compromise) lets an attacker decrypt user IDs and see *per-server* "account A ≈ account B" links and coarse device facts (screen size, time zone). **Still no IP**, because the IP is never stored and the prefix MAC needs the KMS key, which only works through rate-limited, logged calls. This is the honest worst case. Publish it (§8).
- **Cross-server linking:** different K_g per server means the same browser produces unrelated hashes in two servers. We cannot build a network later without every user re-verifying. That is the point.
- **Crypto-shredding:** delete `wrap(K_g)`, and every row for that guild becomes permanently unreadable, including rows in backups.
- **Rotation:** K_master rotates yearly (KMS handles it). K_g can't be rotated without the raw signals, so it lives until the guild's data expires. Signals are re-hashed at each re-verification.
- **KMS choice:** AWS KMS or GCP Cloud KMS, both of which support HMAC keys. **Cost is unverified.** Envelope decrypts are cached in memory for ≤10 minutes per guild, so only a handful of KMS calls happen per verification. If you don't want a cloud KMS, the fallback is a separate small "key service" process on another host. It's weaker and more work.

#### 4.3 Matching rules (starting point; tune on real data)

Score a new verification against each stored record in the same guild:

| Rule | Result |
|---|---|
| Same device token | **Strong** |
| ≥4 of {canvas, WebGL, audio, fonts} equal, **and** time zone, language and screen equal | **Strong** |
| 3 of those high-entropy components equal, plus time zone and screen equal | **Medium** |
| IP prefix equal plus ≥2 high-entropy components equal | **Medium** |
| IP prefix alone, or low-entropy signals only | **No match** (household or CGNAT) |
| iOS/iPadOS Safari, no device token: WebGL and canvas match only | Downgraded one level (identical iPhones) |
| Signals look noised (Brave or resistFingerprinting detected) | Low-confidence. **Never punished**; noted for moderators |

- Match against **banned** records: Strong goes to Review (or Hold role if the server opts in). Medium goes to Review.
- Match against **active member** records (multi-accounting): flag only, by default. Many servers allow alts.

**Honest trade-off:**
- *False positives* will be lower than IP bots for households and CGNAT, because the IP is never decisive. But same-model phones and shared family computers will still collide. Moderators review rather than the bot acting, which contains the damage.
- *False negatives* will be **higher than DC**. A second browser, incognito plus a privacy browser, a second device, or a cleared device token on mobile will usually get through. We stop casual ban evasion. We do not stop a determined evader. **Say this on the website.** Admins who need maximum catch rates should know we chose privacy on purpose.
- No published accuracy figures until we have measured them: track the moderator Allow/Deny outcome on flagged cases (§15).

### 5. Handling matches

- **The mod queue message** (in the review channel): "New member @X needs review — device strongly matches **@Y (banned 3 Mar)**, matched on: device token. [Allow] [Keep unverified] [Mark as alt] [Details]". Showing @Y is fine here, because the moderators banned @Y themselves and nothing from another server is shown.
- **The verifying user is never told** who they matched, or that it was a match. They only see "a moderator will review".
- **No automatic bans.** "Mark as alt" just records the decision. Moderators use Discord's own ban.
- **Appeals:** the review-pending page and the bot DM include an "Explain your situation" form (a modal, 500 characters), sent to the queue. Typical case: "my brother is banned, we share a PC".
- **Expiry:** a flag lapses when the matched banned record expires (§9). "Allow" clears it permanently for that pair.
- **Audit:** we record which moderator decided what and when (per guild, deleted with the guild).

### 6. Data inventory

| Field | Why | Protection | Deleted when |
|---|---|---|---|
| `guild_id` (plaintext) | Routing, settings, billing | DB encryption at rest | Bot removed, then immediately (§9) |
| Guild settings (role/channel IDs, policies) | Run the bot | At rest | Bot removed, then immediately |
| `wrap(K_g)` | Per-guild key | KMS-wrapped; key table backed up separately, 7-day backup life | Bot removed, then immediately (this is the crypto-shred) |
| `uid_tag` = HMAC(K_g, user_id) | Find a user's rows for deletion and status | Keyed hash | With the record |
| `user_id_ct` | Tell moderators who matched | AES-GCM under K_g | With the record |
| `stored_s` per signal (~10) | Matching | Two-layer keyed hash (§4.2) | With the record |
| `ip_prefix_mac` (optional) | Weak supporting signal | KMS MAC, never decisive | **30 days** max, even if the record lives longer |
| `status` (member / banned / left), timestamps | Retention and matching | At rest | With the record |
| `vpn/datacenter/tor` booleans | Show the policy outcome to moderators | At rest | 30 days |
| Mod decisions (pair, action, moderator ID, time) | Audit, avoid re-flagging | Encrypted under K_g | With the guild, or when either record expires |
| Appeal text | Moderator review | Encrypted under K_g | 30 days after decision |
| One-time verify tokens | Bind link to user | Signed, 10-minute expiry, single-use nonce | TTL 1 hour |
| Billing (Polar customer/subscription IDs) | Plus | As PinPal | Per Polar and tax law; never mixed with verification data |
| **Never stored** | Raw IP, IP location, ASN/ISP, email, full UA, raw fingerprint values, Discord username or avatar | | |

Record retention per guild (admin picks within limits; the default is in bold):
- Members: kept while they're in the server. When they leave, **30 days** (catches leave-and-rejoin). If the bot can't see leaves (no privileged intent), the record expires **90 days** after last verification instead.
- Banned: **6 months** after the ban (choice: 1–12 months), deleted at once on unban (`GUILD_BAN_REMOVE` event).
- **Retention is not a paid upsell.** The maximum is the same for everyone.

### 7. Security architecture

#### 7.1 Principles
Least data, least privilege, no inbound ports except one small web endpoint, no human browsing of records, everything written down.

#### 7.2 Components

```
[User browser] --HTTPS--> [CDN/edge: static verify page + WAF/rate limit]
                               |
                               v
                     [verify-web: tiny stateless API]   (only public thing)
                       - IP checks in memory, KMS-MAC prefix
                       - seals raw signals to matcher pubkey
                       - writes job to queue (insert-only DB user)
                               |
                         [MongoDB: jobs / records]  (private network only)
                               ^
                               |
                     [matcher+bot: no inbound ports]   (like PinPal)
                       - Discord gateway (outbound)
                       - unseals, hashes, matches, posts to mod queue
                       - KMS decrypt for K_g
```

- **verify-web** cannot read records, guild keys or the bot token. If compromised, the attacker sees live submissions from then on (unavoidable), but no history.
- The **matcher** has the bot token and can use KMS. It is the crown jewel: it has no inbound ports, a minimal OS, and auto-applied security updates.
- Separate DB users: `web_insert` (insert jobs only), `matcher_rw` (records), `ops_readonly_counts` (aggregation views only).

#### 7.3 Encryption
- In transit: TLS 1.2+ everywhere, HSTS on the verify domain, TLS to MongoDB.
- At rest: disk/DB encryption from the host, **plus** app-level encryption (§4.2), so a disk-level or DB-level leak is not enough on its own.
- Backups: encrypted, 7-day life, a separate account or bucket with object lock. Key-table backups are on the same 7-day life, so crypto-shredding completes within 7 days.

#### 7.4 Key management
- KMS master key (wrap/unwrap) and HMAC key: IAM allows only the matcher's (or web's, for the MAC) workload identity. No user can call decrypt day-to-day, including you. Break-glass access needs a separate account with hardware 2FA and raises an alert.
- KMS usage alerts: unusual decrypt volume pages you.
- **The kill switch:** disabling the KMS key makes every stored record unreadable instantly. Document it in the incident runbook (§10).

#### 7.5 Secrets
- No `.env` files on disk in production. Use the platform secret store, injected at start. No long-lived cloud access keys anywhere (workload identity / OIDC). The DC attacker found cloud credentials on a forgotten box.
- Separate Discord application, Polar token, database and cloud project from PinPal.
- Secret scanning on the repo (GitHub secret scanning plus a pre-commit hook). `.gitignore` excludes logs and env files from the first commit.

#### 7.6 Discord bot token and permissions
- Request **only**: View Channel, Send Messages, Embed Links, Manage Roles (to grant the verified role). **No** Ban, Kick, Administrator, Manage Messages, Manage Server, or Mention Everyone.
- Intents: `guilds`, `guild_moderation` (ban add/remove events, not privileged). `guild_members` (privileged) is optional, to see leaves. Start without it.
- So a stolen token can post in the channels we can see and grant or remove *roles below ours*. That is bad, but nothing like mass bans. Tell admins to keep our role just above the verified role.
- Rotate the token every 90 days, and after any personnel or machine change. Alert on unexpected gateway sessions where possible.

#### 7.7 Network exposure and logging
- The only public listener is verify-web, behind CDN rate limiting. MongoDB, metrics and admin tools sit on a private network or VPN only. Keep an **infrastructure inventory file** in the repo, reviewed monthly. Decommission checklist: delete the machine, delete its credentials, delete its DNS records, update the inventory.
- **Logs never contain IPs, user IDs or signals.** The CDN and web server log formats are changed to drop the client IP, or keep it for at most 24 hours for abuse rate limiting. Check what the CDN keeps by default. **[Unverified per provider]**
- Owner metrics: daily counts only (verifications, flags, decisions per outcome). No record lookup tool, and no in-Discord DB editor like PinPal's.

#### 7.8 Dependencies and code
- Pinned dependencies plus Dependabot. Weekly patch window.
- The verify page is open source, with Subresource Integrity on any external script (ideally none).
- The hashing, matching and deletion modules are small, fully unit-tested (PinPal's `pinkit` style) and reviewed by someone else before launch: a paid security review if the budget allows (a few days' work).

### 8. Threat model

| Threat | Impact | Mitigation | Residual |
|---|---|---|---|
| Attacker dumps the DB (Metabase-style) | Opaque bytes | App-level encryption; keys in KMS | **Low** |
| Attacker gets the matcher host | Decrypts per-server links and coarse device data; uses the bot token | No inbound ports, patching, KMS alerts, kill switch | **Medium**: per-server "A ≈ B" links leak. **No IPs.** |
| Attacker gets verify-web | Sees new submissions and live IPs while inside | Stateless, insert-only, alerting, minimal code | Medium for the duration |
| Stolen bot token | Spam in visible channels, role changes | Minimal permissions, rotation | Low–medium |
| Stolen Polar token | Billing tampering | Separate token, scoped, outbound polling only | Low |
| User spoofs fingerprint / evades | Gets in | Accepted: moderators and Discord's own tools remain | **High, by design** |
| User poisons signals to frame someone | Innocent person flagged | Needs their device token or full device; moderator review; appeals | Low |
| Malicious server admin wants to unmask members | Wants to know who someone is | Admins only see links *within their own server* | Low |
| Insider (you), or someone coercing you | Reads data | No browse tool; KMS break-glass alerts; per-server keys; published transparency | Medium: be honest that the operator *could* modify code to log IPs going forward. Open-source page and reproducible builds reduce, not remove, this. |
| Legal demand for data | Must disclose | Little exists to give: no IPs, encrypted per-server links | Low; publish a transparency report |
| DDoS on the verify page | New members can't verify | CDN, rate limits, mod manual verify as fallback | Medium |

**What a full leak reveals (put this on the website):** for each server, which Discord accounts (by ID) moderators should consider "probably the same device", plus coarse device facts (screen size, time zone, browser family). **Never IP addresses, locations, emails or ISPs, and nothing that links one server's members to another's.**

### 9. Deletion and retention

- **User self-delete:** `/privacy` (in any server with the bot) or the "Delete my data" link on the verify page (re-authenticated by a fresh one-time token).
  - *Member records:* deleted immediately, and the user loses the verified role in that server.
  - *Banned records:* the user can't remove a ban-evasion record by themselves (legitimate interest in keeping it; GDPR Art. 17(3)/21 balancing **[Lawyer]**). The request goes to that server's moderators, and the record still expires on its normal schedule. Tell the user this plainly.
  - The user gets a confirmation listing what was deleted (counts per server, no server names unless they're a member).
- **Server removes the bot (`on_guild_remove`):** delete `wrap(K_g)` at once (crypto-shred), then hard-delete rows within 24 hours. Backups expire within 7 days. Unlike PinPal's 30-day holding period, **there's no restore**, and setup says so.
- **Admin "delete all data" button** in `/setup`: same as removal, but the bot stays.
- **Automatic:** MongoDB TTL indexes on `expires_at` for every collection, plus a nightly job that checks nothing is past expiry and alerts if anything is.
- **Proving deletion:**
  1. A deletion receipt (an ID plus a timestamp) given to the requester.
  2. A deletion log with counts only, no identifiers.
  3. A monthly automated check that sample-queries deleted `uid_tag`s, all returning nothing.
  4. A public "how deletion works" page that explains crypto-shredding.
- **Shutdown:** 30 days' notice, then disable and schedule deletion of the KMS keys, which makes everything unreadable. Publish a closing statement.

### 10. Incident response

**First hour**
1. Reset the bot token (Developer Portal). Revoke DB and cloud credentials. Set verify-web to a static maintenance page.
2. If key material or the matcher might be compromised: **disable the KMS keys**. All data becomes unreadable, and the bot drops to "manual verify only" mode.
3. Preserve logs and snapshots for investigation, without copying user data around.
4. Post a short holding notice on the status page and support server: "we're investigating an incident, verification is paused".

**First day**
5. Work out the scope: what was reachable, for how long, and which keys.
6. Notify Discord developer support. Get legal help.
7. Regulators: GDPR Art. 33 within 72 hours if EU personal data is likely affected [own knowledge]. Australia's Notifiable Data Breaches scheme if it applies (assess within 30 days) [own knowledge; depends on the small-business exemption]. Pick a lead EU authority in advance. **[Lawyer]**
8. Publish what we know and what's being done, in plain words. Say what a leak *can't* contain (§8).

**First week**
9. Root-cause write-up, published. Fix it, and get an independent review.
10. Message server owners through the bot (one message, to the owner, opt-out respected) and the support server.
11. Rotate everything. New K_g per guild means users re-verify. Accept the friction.
12. Re-enable gradually, and only after review.

**Prepare now:** a written runbook in the repo, a status page, the lawyer's contact, regulator templates, and a quarterly 30-minute drill ("token leaked, go").

### 11. UX

- **`/setup` panel** (PinPal style, about 4 screens): Role, then Channels (verify and mod queue), then Policies (VPN: Allow / **Review** / Block; Strong matches: **Review** / Hold role; Retention), then Post the verify message. Each screen gives a one-line "what this means for members' privacy".
- **Member experience:** about 2 clicks plus a short captcha, under 10 seconds. Works on mobile. No login.
- **Moderator queue:** one message per case with buttons. Nothing to memorise.
- **Coming from Double Counter (guide page plus `/setup` notice):**
  - "Your Double Counter ban history **won't** come with you. Nobody can move it, and we wouldn't accept it." (That would mean importing IP-derived data.)
  - Seed the database: optionally ask **existing members to verify** within N days ("re-verify campaign"). Then, when someone is banned later, their device is already known.
  - Discord's own bans still block the original accounts. We add *new* coverage from now on.
  - Set expectations: "for the first weeks we'll catch less than you're used to; in exchange, nothing about your members can leak like it did on 4 October."
  - Settings mapping table: DC setting → our closest setting, or "deliberately not offered".

### 12. Pricing

- **Free (everything that matters for safety and privacy):** verification, alt matching, VPN/Tor checks, mod queue, appeals, manual verify, all deletion tools, the same retention limits.
- **Plus — $4.99/mo per server via Polar** (same as PinPal+, same billing code):
  - Custom verify page branding (logo, colours, text)
  - Multiple verification flows and roles
  - Rule acceptance or questions before verifying
  - Aggregate stats (counts and trends)
  - Mod queue extras (notes, assigning moderators)
  - CSV export of mod decisions
  - Priority support
- **Never paywalled:** privacy and security basics, deletion, appeals, shorter retention. And never "block privacy browsers" (contrast with AuthenticateMe).
- An optional **PinPal + verification bundle** discount for existing PinPal+ servers.

### 13. Launch and distribution

1. **PinPal first:** the `/setup` and docs footers in PinPal mention the new bot. One opt-out-respecting announcement to PinPal server owners, no mass DMs. Re-read PinPal's own DM rules first: PinPal has a `dm_log` to avoid repeat DMs.
2. Bot lists: top.gg, discordbotlist and others. Put privacy in the first line of the listing.
3. Pages:
   - "Alternative to Double Counter"
   - "Privacy-first verification bot comparison"
   - "How our verification works (and what a leak would reveal)"
   - The data inventory table
   - The open-source repo link
4. **Talking about the breach honestly:** state facts with links, and no gloating. Example wording: "In October 2026 Double Counter disclosed a breach that exposed stored IP addresses. We built [bot] so there are no IP addresses to expose. Here's exactly what we store." Never say "unhackable". Never claim better accuracy. Credit DC where it's fair (fast disclosure, regulator notification).
5. Before launch: get one or two respected Discord moderators or community security people to review the privacy page.

### 14. Maintenance budget (blunt)

This is **not** a PinPal-level "minimal maintenance" bot. PinPal has no public endpoint and no adversaries. This has both.

| Phase | Hours/week |
|---|---|
| Build v1 (verify page, matcher, setup, deletion, tests, docs) | ~10–15 h/week for **8–12 weeks** |
| Steady state, under 2k servers | **3–5 h/week**: support (mostly "why am I under review?" that moderators should handle), dependency patches, list refreshes (automated), metrics check |
| Steady state, 10k+ servers | **6–10 h/week** |

What pushes it up:
- Browser changes that break signals (Safari, Chrome and Firefox privacy updates; a quarterly signal review)
- Evasion tooling aimed at us once we're popular
- DDoS on the verify page
- Data requests, legal queries, possible regulator contact
- Discord policy changes
- Any incident (a week of full-time work, easily)
- Becoming the "Double Counter replacement" in the news

Ways to keep it down: no cross-server features, no OAuth, no auto-actions, managed hosting and KMS, a strong FAQ, and moderators (not you) handle appeals.

### 15. Metrics and stop rules

| | 1 month | 3 months | 6 months |
|---|---|---|---|
| Servers installed | 300 | 2,000 | 8,000 |
| Verification completion (started → verified or review) | ≥85% | ≥90% | ≥90% |
| Moderator "Allow" rate on **Strong** flags (proxy for false positives) | measure | ≤25% | ≤15% |
| Support load | ≤5 h/week | ≤5 h/week | ≤8 h/week |
| Plus conversion | — | ≥1% | ≥2% |
| Security | 0 incidents; deletion checks pass | same | external review done |

**Stop rules** (shut down cleanly per §9 if any of these hold):
- Strong-flag Allow rate is still >50% after two tuning rounds (the detection isn't useful).
- Under 1,000 servers at 6 months **and** under 1% Plus conversion.
- More than 10 h/week for 8 consecutive weeks with no path to reduce it.
- A lawyer says consent or the lawful basis is unworkable in the EU or UK without changes that break the design.
- Discord's policy bans external fingerprinting verification.
- A breach exposing decryptable data. Then a hard review, not automatic shutdown, but it is on the table.

### 16. Open questions and risks, ranked

1. **Legal basis and consent for fingerprinting** in the EU and UK (is it "strictly necessary" or consent; controller or processor; minors). High impact. **[Lawyer]** before launch.
2. **Detection may be too weak to be worth installing.** Fingerprint-only matching misses many alts, and admins may judge us against DC's numbers. Mitigation: be honest, measure, and offer the optional IP-prefix signal.
3. **The current Discord Developer Policy** could not be read here. Confirm external verification pages and fingerprinting are allowed.
4. **Public web endpoint:** new attack surface and DDoS risk for a solo developer.
5. **The operator-trust problem:** "never stores IP" is a promise only code review and transparency can support. Mitigation: open source, published architecture, an external review.
6. **Crowded market:** DC (if re-enabled), AuthenticateMe, Verification, Verifeon, plus Discord's own native tools. The DC install block may be lifted, so the window may be short.
7. **KMS cost and vendor lock-in.** Unverified pricing; check before choosing.
8. **Identical-device collisions** (families on the same iPhone model). Moderator review contains them, but they will annoy people.
9. **Hosting unknown:** where PinPal runs determines how much of this is reusable.
10. **Naming and branding:** not chosen.

---

## Sources

- Breach: [HIBP](https://haveibeenpwned.com/Breach/DoubleCounter) · [Outlook Respawn](https://respawn.outlookindia.com/gaming/gaming-news/double-counter-discord-breach-exposes-millions-of-user-records) · [tech-insider](https://tech-insider.org/double-counter-discord-breach-28-million-accounts-2026/) · [DigitalCitizen](https://www.digitalcitizen.life/double-counter-discord-bot-breach-275000-emails/) · [rocket-boys (JP)](https://rocket-boys.co.jp/?p=43025) · [gblock](https://www.gblock.app/articles/double-counter-discord-bot-breach-28-million-2026) · [IntCyberDigest](https://x.com/IntCyberDigest/status/2116922462592241982) · [Pirat_Nation](https://x.com/Pirat_Nation/status/2107796290461466941) · [egamers](https://egamers.io/discord-blocks-new-installs-of-double-counter-after-hacker-hijacks-the-security-bot/) · [techjournal](https://techjournal.org/discord-double-counter-breach) · [ipregistry](https://ipregistry.co/blog/double-counter-breach-ip-address-retention)
- Double Counter: [site](https://doublecounter.gg/) · [features](https://doublecounter.gg/features) · [FAQ](https://doublecounter.gg/faq) · [verification bot page](https://doublecounter.gg/discord-verification-bot) · [privacy policy](https://docs.doublecounter.gg/double-counter-en/legal) · [alt detections docs](https://docs.doublecounter.gg/double-counter-en/alt-detections-and-vpn-intrusions) · [Doogle docs](https://docs.doublecounter.gg/double-counter-en/doogle) · [Doogle page](https://doublecounter.gg/doogle-the-ultimate-discord-alt-account-detection-tool) · [tellter Doogle](https://tellter.com/projects/doogle) · [top.gg](https://top.gg/bot/703886990948565003) · [Peakbot: is DC safe](https://peakbot.pro/blog/is-double-counter-safe) · [lina.sh critique](https://lina.sh/-dcounter)
- Competitors: [AuthenticateMe docs](https://docs.authenticateme.xyz/en/owners-manual) · [top.gg 1011135011413577768](https://top.gg/bot/1011135011413577768) · [Peakbot Wick vs VaultCord](https://peakbot.pro/blog/wick-vs-vaultcord-2026) · [Verifeon top.gg](https://top.gg/cs/bot/1542559582990110790) · [Beemo docs](https://github.com/beemobot/docs.beemo.gg/blob/main/index.md) · [BetterAntispam vs DC](https://betterantispam.com/en/blog/betterantispam-vs-double-counter)
- Complaints: [lokamc CGNAT case](https://forums.lokamc.com/threads/traqsoul-unban-appeal.10477/latest) · [Nextcloud CGNAT](https://help.nextcloud.com/t/what-cg-nat-is-how-to-detect-it-why-it-is-bad-what-can-you-do-about-it/201908)
- Rules: [Discord Developer Terms](https://support-dev.discord.com/hc/en-us/articles/8562894815383-Discord-Developer-Terms-of-Service) · [2022 Developer Policy](https://support-dev.discord.com/hc/en-us/articles/25280499088279-2022-Discord-Developer-Policy) · [2017 Developer Terms](https://support-dev.discord.com/hc/en-us/articles/25280443568791-2017-Discord-Developer-Terms-of-Service) · [EDPB 2/2023](https://www.edpb.europa.eu/documents/530_en) · [Hunton on 2/2023](https://hunton.com/privacy-and-information-security-law/edpb-publishes-guidelines-to-clarify-scope-of-eu-cookie-notice-and-consent-requirements) · [Stibbe on EDPB pseudonymisation](https://stibbe.com/publications-and-insights/key-takeaways-and-insights-from-the-edpb-pseudonymisation-guidelines) · [EDPB 01/2025](https://www.edpb.europa.eu/our-work-tools/documents/public-consultations/2025/guidelines-012025-pseudonymisation_en?page=4) · [DLA Piper on ICO fingerprinting](https://privacymatters.dlapiper.com/2025/01/googles-u-turn-on-device-fingerprinting-icos-response-and-subsequent-guidance/) · [Mondaq ICO 2026](https://www.mondaq.com/uk/privacy-protection/1794984/ico-cookie-crackdown-20-the-icos-new-storage-and-access-technologies-guidance) · [MinterEllison AU reforms](https://www.minterellison.com/articles/privacy-and-other-legislation-amendment-act-2024-now-in-effect) · [Mondaq AU reforms](https://www.mondaq.com/australia/privacy-protection/1640630/australias-ongoing-privacy-reforms-bolstering-australias-privacy-regulatory-framework)
- Fingerprinting: [Browser fingerprinting survey](https://arxiv.org/pdf/1905.01051) · [FP-Stalker](https://hal.archives-ouvertes.fr/hal-01652021) · [Brave community on farbling](https://community.brave.com/t/fingerprinting-how-do-we-know-its-actually-working/134536) · [ipcheck fingerprinting explainer](https://docs.ipcheck.ing/knowledge-base/concepts/browser-fingerprinting)
