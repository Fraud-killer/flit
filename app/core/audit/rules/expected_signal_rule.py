"""
Absence as evidence.

Every other rule scores something that happened. This one scores something
that did not: an event that failed to produce the signals this merchant's
traffic normally produces.

It matters because FLIT's risk score is built only from rules that fired, so
an event carrying nothing scores near zero and is indistinguishable from an
event that is genuinely fine. That makes emitting nothing the optimal strategy
against the system. This rule closes that: if the overwhelming majority of a
merchant's users produce a device key and this one did not, the omission is
itself the finding.

It is calibrated per application rather than absolutely, so a merchant who has
not deployed device collection yet is never punished for it.
"""

import logging
from datetime import timedelta

from asgiref.sync import sync_to_async
from django.core.cache import cache
from django.utils import timezone
from devkit.message import Message

from core.audit.events import ClientEvent, TransactionEvent, RegistrationEvent
from core.identity_keys import IdentityKeyType

from .base_rule import BaseRule, Maturity, RuleKind


logger = logging.getLogger(__name__)


# Below this many recent decisions there is no baseline worth trusting.
MIN_SAMPLE = 50

# Below this share of device-bearing traffic, assume the merchant has not
# rolled out device collection and stay quiet.
MIN_BASELINE = 0.3

BASELINE_WINDOW_DAYS = 7
BASELINE_SAMPLE_CAP = 1000
BASELINE_CACHE_SECONDS = 300


def _baseline(application_id):
    """
    The share of this application's recent decisions that carried a device
    key, and the sample it came from.
    """
    from core.models import AuditLog

    recent = list(
        AuditLog.objects.filter(
            application_id=application_id,
            timestamp__gte=timezone.now() - timedelta(days=BASELINE_WINDOW_DAYS),
        )
        .order_by("-timestamp")
        .values_list("device_fingerprint", flat=True)[:BASELINE_SAMPLE_CAP]
    )

    if not recent:
        return 0.0, 0

    with_device = sum(1 for fingerprint in recent if fingerprint)
    return with_device / len(recent), len(recent)


@sync_to_async
def _cached_baseline(application_id):
    key = f"flit:device_baseline:{application_id}"

    try:
        cached = cache.get(key)
        if cached is not None:
            return cached

        result = _baseline(application_id)
        cache.set(key, result, BASELINE_CACHE_SECONDS)
        return result
    except Exception:
        # No baseline means no finding. Like the rest of FLIT's intelligence,
        # this rule enriches a decision and must never fail one.
        logger.warning("Could not read device baseline", exc_info=True)
        return 0.0, 0


class ExpectedSignalRule(BaseRule):
    """Flags an event that produced less identity signal than this merchant's own traffic normally does."""

    techniques = ("F1002", "F1023")
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_signup_defence.py::TestAbsenceAsEvidence"

    @property
    def applies(self):
        return isinstance(
            self.event, (ClientEvent, TransactionEvent, RegistrationEvent)
        )

    async def perform(self):
        ladder = self.scope.identity_ladder

        if ladder is None or ladder.has(IdentityKeyType.DEVICE):
            return None

        baseline, sample = await _cached_baseline(self.application.id)

        if sample < MIN_SAMPLE or baseline < MIN_BASELINE:
            return None

        # The more reliably this merchant's users identify themselves, the
        # more it means that this one did not.
        severity = round(min(0.4 + 0.55 * baseline, 0.95), 4)

        return Message(
            code="missing_expected_device_signal",
            path="visit_token",
            text=(
                f"No device key resolved, though {baseline:.0%} of this "
                f"application's recent traffic produced one"
            ),
            context=dict(
                severity=severity,
                coverage=ladder.coverage,
                missing=ladder.missing_expected,
                baseline_device_rate=round(baseline, 3),
                baseline_sample=sample,
                resolved_keys=[rung.key_type for rung in ladder.rungs],
            ),
        )
