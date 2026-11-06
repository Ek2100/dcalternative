"""Basic alt detection: compare one verification with stored records.

The inputs are keyed hashes from the same server (see core.crypto), so this
module only ever compares opaque strings for equality.

Rules (deliberately conservative; see docs/verification-bot-plan.md §4.3):
* Same device token (a random ID our page keeps in the browser)    → STRONG
* All 4 high-entropy traits equal, and screen, time zone, language  → STRONG
* 3 high-entropy traits equal, and screen and time zone equal       → MEDIUM
* All 4 high-entropy traits and the screen equal (time zone changed) → MEDIUM
* Anything less, or low-entropy traits only                         → no match
* iPhones/iPads without a device-token match are downgraded a level,
  because identical models produce near-identical canvas and WebGL output.
We never store or compare IP addresses, so shared Wi-Fi, households and
mobile carriers (CGNAT) cannot cause a match on their own.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.signals import HIGH_ENTROPY

NONE, MEDIUM, STRONG = 0, 1, 2
LEVEL_NAMES = {NONE: "none", MEDIUM: "medium", STRONG: "strong"}

VPN_POLICIES = ("allow", "review", "block")


@dataclass(frozen=True)
class Match:
    level: int
    reasons: tuple[str, ...] = ()


def _eq(a: dict, b: dict, name: str) -> bool:
    va, vb = a.get(name), b.get(name)
    return bool(va) and va == vb


def compare(new: dict, old: dict, *, ios: bool = False) -> Match:
    """Compare two {signal: keyed-hash} dicts from the same server."""
    if _eq(new, old, "device"):
        return Match(STRONG, ("same browser (device token)",))

    high = [n for n in HIGH_ENTROPY if _eq(new, old, n)]
    env = all(_eq(new, old, n) for n in ("screen", "tz", "lang"))
    screen_tz = _eq(new, old, "screen") and _eq(new, old, "tz")

    if len(high) == len(HIGH_ENTROPY) and env:
        level = STRONG
    elif (len(high) >= 3 and screen_tz) or (len(high) == len(HIGH_ENTROPY) and _eq(new, old, "screen")):
        level = MEDIUM
    else:
        return Match(NONE)

    if ios:
        level -= 1
        if level == NONE:
            return Match(NONE)
    return Match(level, (f"{len(high)} of {len(HIGH_ENTROPY)} browser traits",))


def candidate_query(sigs: dict) -> list[dict]:
    """Mongo $or clauses that find records that could possibly match."""
    return [{f"sig.{n}": sigs[n]} for n in ("device", *HIGH_ENTROPY) if sigs.get(n)]


@dataclass
class Outcome:
    action: str                      # "verify" | "review" | "block"
    reasons: list[str] = field(default_factory=list)


def is_anonymised(net: dict) -> bool:
    return bool(net.get("vpn") or net.get("tor") or net.get("datacenter"))


def decide(*, net: dict, vpn_policy: str, banned_matches: list[Match]) -> Outcome:
    """Turn network flags and matches into what happens next.
    Matches against *current members* never block; the caller only notifies mods."""
    reasons: list[str] = []
    anon = is_anonymised(net)
    if anon and vpn_policy == "block":
        return Outcome("block", ["VPN, proxy, Tor or datacenter network"])
    if anon and vpn_policy == "review":
        reasons.append("VPN, proxy, Tor or datacenter network")
    best = max((m.level for m in banned_matches), default=NONE)
    if best >= MEDIUM:
        reasons.append(f"{LEVEL_NAMES[best]} match with a banned account")
    return Outcome("review" if reasons else "verify", reasons)
