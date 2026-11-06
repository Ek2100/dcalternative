"""Validation of the browser signals sent by the verification page.

Everything from the browser is untrusted: only known keys are kept, each value
must match a strict pattern, and anything else is dropped (treated as missing).
The bot re-validates after unsealing a job, so a compromised web tier still
cannot push odd data into the matcher.
"""

from __future__ import annotations

import re
from typing import Any

# Signals in the order they are stored. "uafam" is derived from the
# User-Agent header by the web tier; the full User-Agent is never kept.
SIGNAL_NAMES = ("device", "canvas", "webgl", "audio", "fonts",
                "screen", "tz", "lang", "platform", "hw", "uafam")
HIGH_ENTROPY = ("canvas", "webgl", "audio", "fonts")

_HEX64 = r"[0-9a-f]{64}"
_PATTERNS = {
    "device": re.compile(r"[A-Za-z0-9_-]{43}"),
    "canvas": re.compile(_HEX64),
    "webgl": re.compile(_HEX64),
    "audio": re.compile(_HEX64),
    "fonts": re.compile(_HEX64),
    "screen": re.compile(r"\d{2,5}x\d{2,5}x\d{1,2}@\d{1,2}(\.\d{1,3})?"),
    "tz": re.compile(r"[A-Za-z0-9_+\-/]{1,64}"),
    "lang": re.compile(r"[A-Za-z0-9,\-]{1,64}"),
    "platform": re.compile(r"[A-Za-z0-9 _\-.()]{1,32}"),
    "hw": re.compile(r"\d{1,3}\|\d{1,3}(\.\d{1,2})?"),
}

UA_FAMILIES = frozenset(
    f"{os_}-{br}"
    for os_ in ("ios", "android", "windows", "mac", "linux", "cros", "other")
    for br in ("chrome", "edge", "firefox", "safari", "opera", "other")
)


def clean_signals(raw: Any) -> dict:
    """Return {name: str | None} for every client signal, plus "noisy" (bool)."""
    raw = raw if isinstance(raw, dict) else {}
    out: dict = {}
    for name, pattern in _PATTERNS.items():
        value = raw.get(name)
        out[name] = value if isinstance(value, str) and pattern.fullmatch(value) else None
    out["noisy"] = raw.get("noisy") is True
    return out


def clean_uafam(value: Any) -> str | None:
    return value if isinstance(value, str) and value in UA_FAMILIES else None


def ua_family(user_agent: str | None) -> str:
    """Reduce a User-Agent to a coarse "os-browser" family. Nothing else is kept."""
    ua = (user_agent or "")[:512]
    if re.search(r"iPhone|iPad|iPod", ua):
        os_ = "ios"
    elif "Android" in ua:
        os_ = "android"
    elif "CrOS" in ua:
        os_ = "cros"
    elif "Windows" in ua:
        os_ = "windows"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        os_ = "mac"
    elif "Linux" in ua:
        os_ = "linux"
    else:
        os_ = "other"

    if "Edg/" in ua or "EdgiOS" in ua or "EdgA/" in ua:
        br = "edge"
    elif "OPR/" in ua or "OPiOS" in ua:
        br = "opera"
    elif "Firefox/" in ua or "FxiOS" in ua:
        br = "firefox"
    elif "Chrome/" in ua or "CriOS" in ua:
        br = "chrome"
    elif "Safari/" in ua:
        br = "safari"
    else:
        br = "other"
    return f"{os_}-{br}"


def is_ios(uafam: str | None) -> bool:
    return bool(uafam) and uafam.startswith("ios-")
