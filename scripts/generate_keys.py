"""Print fresh secrets for .env. Run once per environment:

    python -m scripts.generate_keys

Put MASTER_KEYS and JOB_PRIVATE_KEY only in the bot's environment, and
JOB_PUBLIC_KEY only in the web page's environment.
"""

import secrets

from core.crypto import b64e, generate_job_keypair


def main() -> None:
    kid = "k" + secrets.token_hex(3)
    private, public = generate_job_keypair()
    print("# ── bot only ──")
    print(f"MASTER_KEYS={kid}:{b64e(secrets.token_bytes(32))}")
    print(f"JOB_PRIVATE_KEY={private}")
    print("# ── web only ──")
    print(f"JOB_PUBLIC_KEY={public}")


if __name__ == "__main__":
    main()
