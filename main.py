"""Start everything with one command, like PinPal:

    python3 main.py          # bot + verify page (page on 127.0.0.1:8080)
    python3 main.py bot      # only the Discord bot
    python3 main.py web      # only the verify page

The verify page here uses Flask's built-in server, which is fine for testing.
For production run the page with gunicorn instead (see README), as its own
service with its own .env.
"""

import os
import sys
import threading

from dotenv import load_dotenv

HOST = "127.0.0.1"  # never 0.0.0.0: only Cloudflare Tunnel on this machine should reach it
PORT = int(os.getenv("WEB_PORT", "8080"))


def build_web():
    """Create the page app up front, so config mistakes show before anything starts."""
    from core.config import ConfigError, WebSettings, check_mongo
    from web.app import create_app

    try:
        settings = WebSettings.from_env()
        check_mongo(settings.mongo_uri, settings.db_name, "MONGO_URI_WEB")
        return create_app(settings)
    except ConfigError as exc:
        sys.exit(f"Config error (verify page): {exc}")
    except OSError as exc:
        sys.exit(f"Couldn't open the IP2Proxy database ({exc}). Set IP2PROXY_DB, or VPN_CHECK=off for testing.")


def run_web(app) -> None:
    from werkzeug.serving import make_server

    server = make_server(HOST, PORT, app, threaded=True)
    print(f"Verify page running on http://{HOST}:{PORT}")
    server.serve_forever()


def main() -> None:
    load_dotenv()
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what not in ("all", "bot", "web"):
        sys.exit("Usage: python3 main.py [all|bot|web]")
    if what == "web":
        return run_web(build_web())
    if what == "all":
        app = build_web()
        threading.Thread(target=run_web, args=(app,), daemon=True).start()
    from bot.main import main as run_bot

    run_bot()


if __name__ == "__main__":
    main()
