"""
How much money has left, per credential, channel and application.

The configuration lives on Policy.outflow_limits, in major units:

    {
      "currency": "NGN",
      "per_initiator": {"15m": 5000000, "1h": 10000000, "24h": 50000000},
      "per_initiator_untrusted": {"1h": 2000000, "24h": 5000000},
      "per_channel": {"1h": 50000000},
      "per_application": {"24h": 500000000},
      "off_hours": {"start": "20:00", "end": "07:00",
                    "timezone": "Africa/Lagos", "factor": 0.25},
      "fail": "block"
    }

Each amount is reserved with an atomic increment before the totals are read,
so of any set of concurrent transfers the last to reserve sees all the others.
BlockStreak's get-then-set would let a burst pass together, and a burst is the
attack. A window is held in fifteen buckets, so it can read up to one bucket
longer than its name. That errs towards stopping.

per_initiator_untrusted counts only the debits a credential sends to a
beneficiary it has no trusted history of paying from that account (see
core.services.money_out.BeneficiaryTrust). A business that pays new people can
keep a large per_initiator limit for its usual payees and still cap what one
credential can send to strangers, which is where a drain goes. Its trip stops
only those debits; payments to trusted beneficiaries carry on.

Counters live in the cache. A cache that loses them under-counts, which is why
a cache that cannot be reached is a refusal and not a pass, and why
docs/deployment.md asks for a Redis that does not evict these keys.
"""

import hashlib
from datetime import datetime, time
from decimal import Decimal
from zoneinfo import ZoneInfo

from django.core.cache import cache
from django.utils import timezone


WINDOWS = {"15m": 15 * 60, "1h": 60 * 60, "24h": 24 * 60 * 60}
BUCKETS_PER_WINDOW = 15

SCOPE_KEYS = {
    "initiator": "per_initiator",
    "initiator_untrusted": "per_initiator_untrusted",
    "channel": "per_channel",
    "application": "per_application",
}
APPLICATION_SCOPE_VALUE = "all"

FAIL_BLOCK = "block"
FAIL_REVIEW = "review"


def to_minor(amount):
    """Major units to an integer of minor units, without float drift."""
    return int((Decimal(str(amount)) * 100).to_integral_value())


def parse_clock(value):
    hours, minutes = str(value).split(":")
    return time(int(hours), int(minutes))


class OutflowLimits:
    def __init__(self, raw):
        self.raw = raw
        self.currency = raw["currency"]
        self.fail = raw.get("fail", FAIL_BLOCK)
        self.off_hours = raw.get("off_hours")

    @property
    def watches_untrusted(self):
        return bool(self.raw.get(SCOPE_KEYS["initiator_untrusted"]))

    @classmethod
    def for_policy(cls, policy):
        raw = getattr(policy, "outflow_limits", None)
        return cls(raw) if raw else None

    def is_off_hours(self, now):
        if not self.off_hours:
            return False
        local = now.astimezone(ZoneInfo(self.off_hours["timezone"])).time()
        start = parse_clock(self.off_hours["start"])
        end = parse_clock(self.off_hours["end"])
        if start <= end:
            return start <= local < end
        return local >= start or local < end

    def limits_for(self, kind, now):
        """{window: limit in minor units} for one scope kind, at this moment."""
        configured = self.raw.get(SCOPE_KEYS[kind]) or {}
        factor = Decimal(str(self.off_hours["factor"])) if self.is_off_hours(now) else Decimal(1)
        return {
            window: int(Decimal(to_minor(limit)) * factor)
            for window, limit in configured.items()
        }

    @staticmethod
    def validate(raw):
        """Problems with a proposed configuration, as strings."""
        if not isinstance(raw, dict):
            return ["must be an object"]

        problems = []
        allowed = {"currency", "off_hours", "fail", *SCOPE_KEYS.values()}
        unknown = set(raw) - allowed
        if unknown:
            problems.append(f"unknown keys: {sorted(unknown)}")

        currency = raw.get("currency")
        if not (isinstance(currency, str) and len(currency) == 3 and currency.isupper()):
            problems.append("currency must be a three-letter code")

        if raw.get("fail", FAIL_BLOCK) not in (FAIL_BLOCK, FAIL_REVIEW):
            problems.append("fail must be block or review")

        configured = 0
        for key in SCOPE_KEYS.values():
            limits = raw.get(key)
            if limits is None:
                continue
            if not isinstance(limits, dict) or not limits:
                problems.append(f"{key} must map windows to amounts")
                continue
            for window, limit in limits.items():
                configured += 1
                if window not in WINDOWS:
                    problems.append(f"{key}: window must be one of {sorted(WINDOWS)}")
                if type(limit) not in (int, float) or not 0 < limit < 1e15:
                    problems.append(f"{key}.{window} must be a positive amount")

        if not configured:
            problems.append("at least one limit is required")

        off_hours = raw.get("off_hours")
        if off_hours is not None:
            problems.extend(OutflowLimits._validate_off_hours(off_hours))

        return problems

    @staticmethod
    def _validate_off_hours(off_hours):
        if not isinstance(off_hours, dict):
            return ["off_hours must be an object"]

        problems = []
        try:
            parse_clock(off_hours.get("start"))
            parse_clock(off_hours.get("end"))
        except (TypeError, ValueError):
            problems.append("off_hours start and end must be HH:MM")
        try:
            ZoneInfo(str(off_hours.get("timezone")))
        except Exception:
            problems.append("off_hours timezone must be an IANA name")
        factor = off_hours.get("factor")
        if type(factor) not in (int, float) or not 0 < factor <= 1:
            problems.append("off_hours factor must be above 0 and at most 1")
        return problems


class Reservation:
    """The increments one transfer made, so a refusal can take them back."""

    def __init__(self, keys, amount_minor):
        self.keys = keys
        self.amount_minor = amount_minor


class OutflowWindow:
    @staticmethod
    def _base(application_id, kind, value, window):
        digest = hashlib.sha256(str(value).encode()).hexdigest()[:24]
        return f"flit:outflow:{application_id}:{kind}:{digest}:{window}"

    @staticmethod
    def _bucket_seconds(window):
        return WINDOWS[window] // BUCKETS_PER_WINDOW

    @classmethod
    def _bucket_keys(cls, base, window, now):
        size = cls._bucket_seconds(window)
        current = int(now.timestamp()) // size
        return [f"{base}:{current - offset}" for offset in range(BUCKETS_PER_WINDOW + 1)]

    @classmethod
    def reserve(cls, application_id, scopes, amount_minor, limits, now=None):
        """
        Add a transfer to every scope and report what that does to the limits.

        `scopes` is [(kind, value)], `limits` is {kind: {window: limit}}.
        Returns (reservation, breaches). The transfer stays counted until
        `release` is called.
        """
        now = now or timezone.now()
        reserved, read = [], {}

        for kind, value in scopes:
            for window in limits.get(kind) or {}:
                base = cls._base(application_id, kind, value, window)
                keys = cls._bucket_keys(base, window, now)
                ttl = WINDOWS[window] + 2 * cls._bucket_seconds(window)
                cache.add(keys[0], 0, ttl)
                cache.incr(keys[0], amount_minor)
                reserved.append(keys[0])
                read[(kind, value, window)] = keys

        found = cache.get_many([key for keys in read.values() for key in keys])

        breaches = []
        for (kind, value, window), keys in read.items():
            used = sum(int(found.get(key) or 0) for key in keys)
            limit = limits[kind][window]
            if used > limit:
                breaches.append(dict(kind=kind, value=value, window=window, limit=limit, used=used))

        return Reservation(reserved, amount_minor), breaches

    @staticmethod
    def release(reservation):
        for key in reservation.keys:
            try:
                cache.decr(key, reservation.amount_minor)
            except ValueError:
                # The bucket expired while the decision was made. Nothing to undo.
                pass

    @classmethod
    def reset(cls, application_id, kind, value, now=None):
        """Forget a scope, so a released trip does not trip again at once."""
        now = now or timezone.now()
        keys = []
        for window in WINDOWS:
            keys.extend(cls._bucket_keys(cls._base(application_id, kind, value, window), window, now))
        cache.delete_many(keys)
