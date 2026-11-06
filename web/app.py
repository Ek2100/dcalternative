"""The verification web page (Flask).

Run in production with gunicorn bound to localhost, behind Cloudflare Tunnel:
    gunicorn -w 2 -b 127.0.0.1:8080 "web.app:create_app()"

Security notes
--------------
* The real visitor IP comes from Cloudflare's ``CF-Connecting-IP`` header, and
  only when the request provably came through Cloudflare (see core.netcheck).
* The IP is used for the Turnstile check and the offline VPN lookup, then
  dropped. It is never logged or stored. Flask/werkzeug access logs are off.
* No cookies, no sessions, no third-party scripts except Cloudflare Turnstile
  (loaded only after the visitor agrees). Strict CSP, HSTS, no referrer.
* This process can only read/claim verification links and add sealed jobs. It
  holds the job *public* key, so it can't read jobs back, and it has no
  Discord token or master keys.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, jsonify, render_template, request

from core.crypto import seal_job, session_id, valid_token_format
from core.netcheck import (DisabledVpnChecker, UntrustedSource, VpnChecker,
                           client_ip, cloudflare_says_tor, load_ranges,
                           verify_turnstile)
from core.signals import clean_signals, ua_family

log = logging.getLogger("verify.web")

CSP = ("default-src 'none'; script-src 'self' https://challenges.cloudflare.com; "
       "frame-src https://challenges.cloudflare.com; connect-src 'self'; style-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

PUBLIC_STATUSES = {"new", "submitted", "verified", "review", "blocked", "error"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_app(settings=None, *, db=None, vpn=None, turnstile=None, ranges=None) -> Flask:
    if settings is None:
        from dotenv import load_dotenv

        from core.config import WebSettings

        load_dotenv()
        settings = WebSettings.from_env()
    if db is None:
        from pymongo import MongoClient

        db = MongoClient(settings.mongo_uri, tz_aware=True)[settings.db_name]
    if vpn is None:
        vpn = VpnChecker(settings.ip2proxy_db) if settings.vpn_check else DisabledVpnChecker()
    if turnstile is None:
        turnstile = verify_turnstile
    if ranges is None:
        ranges = load_ranges(settings.cloudflare_ips_file or None)

    # Werkzeug's request log contains the client IP and the link token.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    app.config["SESSION_COOKIE_NAME"] = "__unused"
    sessions = db["verify_sessions"]
    jobs = db["verify_jobs"]

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = ("geolocation=(), camera=(), microphone=(), payment=(), "
                                              "usb=(), interest-cohort=()")
        resp.headers["Cache-Control"] = "no-store"
        resp.headers.pop("Server", None)
        return resp

    def live_session(token: str):
        if not valid_token_format(token):
            return None, None
        sid = session_id(token)
        doc = sessions.find_one({"_id": sid}, {"status": 1, "expires_at": 1, "guild_id": 1})
        if not doc or doc["expires_at"] <= utcnow():
            return sid, None
        return sid, doc

    def trusted_ip():
        try:
            return client_ip(request.remote_addr, request.headers, settings.proxy_mode, ranges)
        except UntrustedSource:
            abort(403)

    @app.get("/")
    def index():
        return render_template("message.html", title="SyntaxHQ Verify",
                               body="Open the verify link the bot sent you in Discord.")

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html")

    @app.get("/healthz")
    def healthz():
        return jsonify(ok=True)

    @app.get("/v/<token>")
    def verify_page(token):
        trusted_ip()
        sid, doc = live_session(token)
        if not doc or doc["status"] != "new":
            return render_template("message.html", title="This link has expired",
                                   body="Links work once and only for 10 minutes. Go back to Discord and "
                                        "press Verify (or “Send me a new link”) to get a fresh one."), 410
        return render_template("verify.html", site_key=settings.turnstile_site_key, cdata=sid[:32],
                               submit_url=f"/v/{token}/submit", status_url=f"/v/{token}/status")

    @app.post("/v/<token>/submit")
    def submit(token):
        ip = trusted_ip()
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="bad_request"), 400
        sid, doc = live_session(token)
        if not doc or doc["status"] != "new":
            return jsonify(error="expired"), 410

        if not turnstile(settings.turnstile_secret, str(body.get("turnstile") or ""), ip,
                         cdata=sid[:32], hostname=settings.turnstile_hostname or None):
            return jsonify(error="captcha"), 403

        net = vpn.check(ip)
        if cloudflare_says_tor(request.headers):
            net = {**net, "tor": True, "checked": True}
        del ip  # not needed past this point

        signals = clean_signals(body.get("signals"))
        payload = {"signals": signals, "net": net, "uafam": ua_family(request.headers.get("User-Agent"))}

        # Claim the link atomically: a link can be used exactly once.
        claimed = sessions.find_one_and_update(
            {"_id": sid, "status": "new", "expires_at": {"$gt": utcnow()}},
            {"$set": {"status": "submitted"}})
        if not claimed:
            return jsonify(error="expired"), 410
        now = utcnow()
        jobs.insert_one({
            "session_id": sid,
            "guild_id": claimed["guild_id"],
            "sealed": seal_job(settings.job_public_key, payload),
            "created_at": now,
            "expires_at": now + timedelta(minutes=15),
        })
        return jsonify(status="submitted"), 202

    @app.get("/v/<token>/status")
    def status(token):
        sid, doc = live_session(token)
        if not doc:
            return jsonify(status="expired")
        s = doc["status"]
        return jsonify(status=s if s in PUBLIC_STATUSES else "error")

    @app.errorhandler(403)
    def forbidden(_):
        return jsonify(error="forbidden"), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("message.html", title="Not found", body="There's nothing here."), 404

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="too_large"), 413

    @app.errorhandler(500)
    def server_error(_):
        return render_template("message.html", title="Something went wrong",
                               body="Please go back to Discord and try again."), 500

    return app
