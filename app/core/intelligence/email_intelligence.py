"""
Email intelligence.

The signup surface is where abuse starts, because it is free. At that moment
there is no device history, no transaction, no travel baseline — often the
only thing an attacker has handed over is an email address. These helpers
turn that one string into signal.

Everything here is pure and synchronous; the rules that use it stay cheap.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


# Providers that ignore dots in the local part. Everyone else treats
# `j.smith` and `jsmith` as different mailboxes, so collapsing dots for them
# would merge real, distinct users.
DOT_INSENSITIVE_DOMAINS = {
    "gmail.com",
    "googlemail.com",
}

# Domains that hand out throwaway inboxes. Deliberately short and high
# confidence — the heuristics below carry the long tail, and a false positive
# here blocks a real signup.
DISPOSABLE_DOMAINS = {
    "uberip.com",
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
    "temp-mail.org",
    "throwawaymail.com",
    "yopmail.com",
    "trashmail.com",
    "getnada.com",
    "dispostable.com",
    "maildrop.cc",
    "fakeinbox.com",
    "sharklasers.com",
    "grr.la",
    "spam4.me",
    "mohmal.com",
    "emailondeck.com",
    "burnermail.io",
    "moakt.com",
    "tempr.email",
    "mailnesia.com",
    "harakirimail.com",
    "einrot.com",
    "spambog.com",
}

# Reserved by RFC 2606 for documentation and testing. Never a real user.
RESERVED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "test",
    "invalid",
    "localhost",
}

# Substrings that give a throwaway provider away even when the exact domain
# is not on the list above.
DISPOSABLE_MARKERS = (
    "tempmail", "temp-mail", "throwaway", "trashmail", "guerrilla",
    "mailinator", "10minute", "minutemail", "disposable", "fakemail",
    "burnermail", "spamgourmet", "getairmail", "mailcatch",
)

# Local parts a human does not choose.
ADVERSARIAL_MARKERS = (
    "pentest", "pen-test", "bugbounty", "bug-bounty", "hackerone",
    "bugcrowd", "synack", "intigriti", "xsstest", "sqltest", "redteam",
)

# Where an epoch could plausibly fall. Anything outside is a coincidence,
# not a generated address.
EPOCH_FLOOR = 1_420_070_400   # 2015-01-01
EPOCH_HORIZON_YEARS = 2


@dataclass
class EmailAnalysis:
    """What one address is worth as a signal."""

    raw: str
    local: str = ""
    domain: str = ""
    root: str = ""
    valid: bool = False

    is_disposable: bool = False
    is_reserved: bool = False
    has_plus_tag: bool = False
    plus_tag: str = ""
    has_epoch_local: bool = False
    epoch_value: Optional[int] = None
    epoch_at: Optional[datetime] = None
    digit_ratio: float = 0.0
    is_adversarial: bool = False

    signals: List[str] = field(default_factory=list)
    context: Dict = field(default_factory=dict)

    @property
    def machine_generated(self) -> bool:
        """The address looks produced by a script rather than chosen."""
        return self.has_epoch_local or self.is_reserved or (
            self.digit_ratio >= 0.5 and len(self.local) >= 10
        )


def _split(email: str):
    if not email or not isinstance(email, str):
        return None, None

    candidate = email.strip().lower()
    if candidate.count("@") != 1:
        return None, None

    local, domain = candidate.split("@")
    if not local or not domain or "." not in domain:
        return None, None

    return local, domain


def normalize_email(email: str) -> Optional[str]:
    """
    The canonical mailbox an address delivers to.

    Collapses plus-tags everywhere and dots on the providers that ignore them,
    so `a.b+tag@gmail.com` and `ab@gmail.com` resolve to one root. Three of the
    accounts in a real September 2026 signup flood differed only by plus-tag.
    """
    local, domain = _split(email)
    if local is None:
        return None

    local = local.split("+", 1)[0]

    if domain in DOT_INSENSITIVE_DOMAINS:
        local = local.replace(".", "")

    if not local:
        return None

    return f"{local}@{domain}"


def is_disposable_domain(domain: str) -> bool:
    if not domain:
        return False

    domain = domain.strip().lower()

    if domain in DISPOSABLE_DOMAINS:
        return True

    return any(marker in domain for marker in DISPOSABLE_MARKERS)


def is_reserved_domain(domain: str) -> bool:
    if not domain:
        return False

    domain = domain.strip().lower()
    return domain in RESERVED_DOMAINS or domain.endswith(".test") or domain.endswith(".invalid")


def find_epoch(local: str):
    """
    A unix timestamp embedded in the local part, or None.

    Bulk signup scripts name accounts after the clock: `figomass1789844680`
    and `figomass1789844685` were five seconds apart. Humans do not do this.
    """
    if not local:
        return None, None

    now = datetime.now(timezone.utc).timestamp()
    horizon = now + EPOCH_HORIZON_YEARS * 365 * 86400

    for run in re.findall(r"\d{9,13}", local):
        for value, divisor in ((int(run), 1), (int(run), 1000)):
            seconds = value / divisor
            if EPOCH_FLOOR <= seconds <= horizon:
                return int(seconds), datetime.fromtimestamp(seconds, tz=timezone.utc)

    return None, None


def redact(email: str) -> str:
    """A form safe to store and show an analyst: `j***@gmail.com`."""
    local, domain = _split(email)
    if local is None:
        return ""

    head = local[0] if local else ""
    return f"{head}***@{domain}"


def analyze(email: str) -> EmailAnalysis:
    """Every signal one address carries, in one pass."""
    result = EmailAnalysis(raw=email or "")

    local, domain = _split(email)
    if local is None:
        return result

    result.valid = True
    result.local = local
    result.domain = domain
    result.root = normalize_email(email) or ""

    if "+" in local:
        result.has_plus_tag = True
        result.plus_tag = local.split("+", 1)[1]
        result.signals.append("plus_tag")

    result.is_disposable = is_disposable_domain(domain)
    if result.is_disposable:
        result.signals.append("disposable_domain")

    result.is_reserved = is_reserved_domain(domain)
    if result.is_reserved:
        result.signals.append("reserved_domain")

    epoch_value, epoch_at = find_epoch(local.split("+", 1)[0])
    if epoch_value is not None:
        result.has_epoch_local = True
        result.epoch_value = epoch_value
        result.epoch_at = epoch_at
        result.signals.append("epoch_local_part")

    digits = sum(character.isdigit() for character in local)
    result.digit_ratio = digits / len(local) if local else 0.0

    result.is_adversarial = any(
        marker in local or marker in domain for marker in ADVERSARIAL_MARKERS
    )
    if result.is_adversarial:
        result.signals.append("adversarial_local_part")

    result.context = dict(
        domain=domain,
        root_preview=redact(result.root) if result.root else "",
        digit_ratio=round(result.digit_ratio, 2),
        plus_tag=result.plus_tag,
        epoch_at=result.epoch_at.isoformat() if result.epoch_at else None,
    )

    return result
