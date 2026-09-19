"""
Counting accounts across the identity ladder.

Shared by the rules that ask "how many accounts sit behind this actor?".
Each walks the ladder strongest-first and reports the strongest key that
breaches its limit — one finding per event, not one per rung, so a single
farm does not get counted three times over.
"""

from asgiref.sync import sync_to_async

from core.identity_keys import IdentityKeyType as Key
from core.models.device_identity import DeviceAccountLink
from core.models.identity import IdentityAccountLink

from .identity_thresholds import NON_CORRELATING_KEYS, limit_for


def correlating_rungs(ladder):
    if ladder is None:
        return []

    return [
        rung for rung in ladder.correlation_rungs()
        if rung.key_type not in NON_CORRELATING_KEYS
    ]


@sync_to_async
def _count(rung, application, field, since):
    """
    Accounts linked to this rung's key.

    The device rung reads DeviceAccountLink, which predates the ladder and is
    still the table ResolveDeviceIdentity writes; every other rung reads
    IdentityAccountLink. One owner per key type, so the two can never drift.
    """
    if rung.key_type == Key.DEVICE:
        queryset = DeviceAccountLink.objects.filter(device=rung.key)
    else:
        queryset = IdentityAccountLink.objects.filter(identity_key=rung.key)

    return queryset.filter(
        application=application, **{f"{field}__gte": since},
    ).count()


async def strongest_breach(rule, *, thresholds, limit_name, field, since):
    """
    The strongest ladder rung whose account count exceeds its limit.

    Returns `(rung, count, limit)` or None. Because the ladder is ordered by
    confidence, the first breach found is the most trustworthy one available.
    """
    for rung in correlating_rungs(rule.scope.identity_ladder):
        limit = limit_for(thresholds, limit_name, rung.key_type)
        if limit is None:
            continue

        count = await _count(rung, rule.application, field, since)

        if count > limit:
            return rung, count, limit

    return None


def severity_for(count, limit, base=0.7, step=0.05, cap=0.95):
    """
    How bad this particular breach is, 0.0–1.0, growing with the overage.

    Severity describes the instance. How much the *kind* of evidence counts
    is carried separately by the rule code's key suffix (`account_farming:ip`),
    which the weight table scales by that key's confidence. Keeping the two
    apart is what stops a weak key from being punished twice.
    """
    return round(min(base + step * (count - limit), cap), 4)


def code_for(name, rung):
    """
    The rule code for a finding on one rung.

    A device match keeps the bare historical code — that is what these rules
    always emitted, and merchant dashboards, saved queries and weight
    overrides are keyed on it. Only the weaker rungs, which are new, take a
    suffix: `account_farming:ip`.
    """
    if rung.key_type == Key.DEVICE:
        return name

    return f"{name}:{rung.key_type}"
