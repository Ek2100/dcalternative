# SyntaxHQ Verify

A privacy-first Discord verification bot that catches alts of banned members **without ever storing IP addresses**.
Same stack as PinPal: Python, discord.py, MongoDB (motor), python-dotenv, plus Flask for the verify page.

- **Member joins:** the bot DMs them a one-time verify link. If their DMs are closed, they use the Verify button in the server.
- **Verify page:** consent screen, then Cloudflare Turnstile, then browser checks. If they pass, the bot gives them the verified role.
- **Possible alt of a banned member, or a VPN** (if the server chose "review"): the case goes to moderators with **Allow in / Keep out** buttons. The bot can't ban or kick anyone.
- **Admins** run `/setup`: verified role, moderator review channel, VPN policy, ban-record retention, welcome DM, alt notices, posting the verify message, and deleting all server data.
- **Members** run `/privacy` to see or delete their data.
- **Never built:** a cross-server network or any "look someone up" feature. Every server has its own key, so it isn't even technically possible.

See [`docs/verification-bot-plan.md`](docs/verification-bot-plan.md) for the research and full plan.

---

## How it fits together

```
 Discord ⇄ bot (python -m bot.main)          no open ports, like PinPal
             │  creates one-time links, processes jobs, gives roles
             ▼
          MongoDB  ◄── web page (gunicorn web.app) ◄── cloudflared ◄── Cloudflare ◄── member's browser
                       only reads/claims links and         (Tunnel: no open ports here either)
                       adds sealed jobs
```

| Piece | Holds | Can't |
|---|---|---|
| **Web page** | Turnstile secret, job **public** key, a DB user that can only read and claim links and insert jobs | Read jobs back, see Discord IDs, use the bot token |
| **Bot** | Discord token, master keys, job **private** key | Be reached from the internet |
| **Database dump on its own** | Opaque bytes | Show IPs (never stored), Discord IDs (encrypted), browser details (keyed hashes) |

### Behind Cloudflare: where the IP comes from
The app never trusts `X-Forwarded-For`. It reads `CF-Connecting-IP`, and **only** when the request provably came through Cloudflare:
- `PROXY_MODE=tunnel` (recommended): `cloudflared` runs on the same machine and gunicorn listens on `127.0.0.1`. The request has to come from loopback.
- `PROXY_MODE=direct`: the TCP peer has to be inside Cloudflare's published IP ranges (bundled in `core/netcheck.py`, override with `CLOUDFLARE_IPS_FILE`).

The IP is used for exactly two things, then dropped: Turnstile's server-side check and an **offline** VPN lookup (IP2Proxy). It's never logged or stored. Cloudflare's `CF-IPCountry: T1` header also flags Tor.

### What gets stored
| Stored | How |
|---|---|
| Discord ID | AES-256-GCM under the server's key, plus an HMAC "tag" so deletion can find it |
| Browser signals: device token, canvas, WebGL, audio, fonts, screen, time zone, language, platform, CPU/RAM, coarse browser family | HMAC-SHA-256 under the server's key. Missing values are never hashed. |
| Status (verified / waiting / kept out / banned / deleting) and dates | Plain |
| **Never** | IP, location, ISP, email, full user-agent, raw signal values |

Each server's key is wrapped by a master key (`MASTER_KEYS`, which supports rotation). Deleting the server's key makes all of that server's rows unreadable (crypto-shredding).

### Alt detection (basic, on purpose)
- **Strong match:** same device token, or all 4 detailed traits plus screen, time zone and language.
- **Medium match:** 3 detailed traits plus screen and time zone, or all 4 plus screen.
- **iPhones and iPads** drop one level unless the device token matches, because identical models look the same.
- **IP is never a signal**, so households and mobile networks don't cause matches.
- **Matching a banned account** sends the case to moderator review. **Matching a current member** only posts a heads-up (this can be turned off).
- **Privacy browsers** (Brave and others that randomise canvas) aren't punished. The noisy signal is simply skipped.

It catches casual alts: same browser, same device. It won't catch someone who switches device or browser. That trade-off is deliberate.

---

## Deletion without letting people delete their way out of a ban

The evidence that catches ban evasion is the **banned account's** record, so the rules are built around protecting that record:

| Situation | What happens |
|---|---|
| A member runs `/privacy` → Delete | They lose the verified role straight away. The record is unreadable at once: the encrypted ID is wiped and the record is never matched again. The leftover hashes are erased after **7 days** (`DELETE_GRACE_DAYS`). |
| …and the server bans them within those 7 days | The record becomes a ban record. Otherwise "break the rules, delete, get banned, come back on an alt" would work. |
| A banned person asks to delete | Their ban record **stays**. It expires on the server's schedule (30–365 days, default 180), or right away if they're unbanned. They're told exactly this. |
| An alt deletes itself | Only the alt is un-verified. The banned main's record is untouched, so the alt matches again next time it verifies. |
| A member leaves | Their record expires 30 days later (`LEFT_RETENTION_DAYS`). |
| A verified member stays | Their record expires 180 days after verifying (`MEMBER_RETENTION_DAYS`). |
| The server presses "Delete all server data", or removes the bot | The server's key is deleted **first**, then every row. If the bot was removed while offline, an hourly check does the same after 24 hours. |
| Unused links / submitted jobs | Expire after 10 / 15 minutes. |

Every collection has a MongoDB TTL index on `expires_at`, so expiry happens even if the bot is down.
Backups: keep them encrypted and **delete them after 7 days or less**, so deletions also reach the backups.

---

## Try it as a Discord bot (about 15 minutes)

1. **Python 3.11+ and MongoDB.** Local `mongod` or Atlas both work.
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements-dev.txt
   ```
2. **Discord app** (https://discord.com/developers/applications): create the bot and copy the token.
   - Under **Bot → Privileged Gateway Intents**, turn on **Server Members Intent**. It's needed for the join DM and for handling leaves.
   - Invite the bot with exactly these permissions (View Channel, Send Messages, Embed Links, Manage Roles):
     `https://discord.com/oauth2/authorize?client_id=YOUR_APP_ID&permissions=268453504&scope=bot+applications.commands`
3. **Keys:**
   ```bash
   python -m scripts.generate_keys
   ```
   Copy `.env.example` to `.env` and paste the generated keys and your token into it.
4. **A public HTTPS URL for the verify page.** The quickest is a free Cloudflare quick tunnel:
   ```bash
   cloudflared tunnel --url http://127.0.0.1:8080
   ```
   Put the `https://….trycloudflare.com` URL in `PUBLIC_BASE_URL`, and keep `PROXY_MODE=tunnel`.
5. **Turnstile:** for a first test, use Cloudflare's always-pass test keys (they're in `.env.example`) and set `TURNSTILE_HOSTNAME=` to blank. Later, create a real widget in the Cloudflare dashboard for your hostname.
6. **VPN database:** either set `VPN_CHECK=off` for the first test, or download the free **IP2Proxy LITE PX2** BIN from lite.ip2location.com (free account) and set `IP2PROXY_DB`.
7. **Run both** (two terminals). Keep `SYNC_COMMANDS=1` on the first start so the slash commands register:
   ```bash
   python -m bot.main
   ```
   ```bash
   gunicorn -w 2 -b 127.0.0.1:8080 "web.app:create_app()"
   ```
8. **In Discord:**
   1. The server owner gets the onboarding DM.
   2. Run `/setup`, pick the role and the mod channel, and lock channels to the verified role.
   3. Press **Post verify message here**.
   4. Join with a second account. You should get the welcome DM, verify, and receive the role.
   5. To test alt detection: ban the first account, then verify a third account **in the same browser**. A review case should appear in the mod channel.

Tests:
```bash
python -m pytest -q
```

---

## Production checklist
- [ ] Run the bot and the web page as **separate services with separate `.env` files**: the web one gets only the web section, the bot one only the bot section.
- [ ] Use two MongoDB users. Example roles:
  ```js
  // web: can only read/claim links and add jobs
  db.createRole({role: "verifyWeb", privileges: [
    {resource: {db: "verify", collection: "verify_sessions"}, actions: ["find", "update"]},
    {resource: {db: "verify", collection: "verify_jobs"}, actions: ["insert"]}], roles: []})
  db.createUser({user: "verify_web", pwd: passwordPrompt(), roles: ["verifyWeb"]})
  db.createUser({user: "verify_bot", pwd: passwordPrompt(), roles: [{role: "readWrite", db: "verify"}]})
  ```
- [ ] MongoDB is **not** reachable from the internet: bind to localhost or a private network, with TLS on Atlas.
- [ ] Cloudflare Tunnel, gunicorn on `127.0.0.1`, no open inbound ports. Add a Cloudflare rate-limit rule on `/v/*/submit`.
- [ ] Don't turn on gunicorn's `--access-logfile`: access logs would contain IPs and link tokens.
- [ ] Real Turnstile keys, with `TURNSTILE_HOSTNAME` set to your verify hostname.
- [ ] Refresh the IP2Proxy LITE database monthly (cron), and check the Cloudflare IP ranges when you deploy.
- [ ] Rotate the bot token every 90 days. For master keys, add a new key **first** in `MASTER_KEYS`; server keys are re-wrapped automatically as they're used.
- [ ] Encrypted backups that expire within 7 days.
- [ ] **Never** add an admin or analytics dashboard on this database to the internet (that's how Double Counter was breached).
- [ ] Before a public launch: get legal advice on the consent wording (EU/UK fingerprinting rules), and publish the `/privacy` page.

## Layout
```
bot/main.py       Discord bot: events, /setup panel, DMs, buttons, mod cases
bot/service.py    verification, matching, bans, deletion (tested without Discord)
web/app.py        Flask verify page, Cloudflare IP handling, Turnstile, VPN check
web/static/       verify.js (consent → Turnstile → signals), style.css
core/crypto.py    keys, keyed hashes, encryption, sealed jobs
core/matching.py  alt-detection rules
core/netcheck.py  Cloudflare client IP, IP2Proxy, Turnstile
core/signals.py   strict validation of browser signals
tests/            unit tests (pytest)
```
