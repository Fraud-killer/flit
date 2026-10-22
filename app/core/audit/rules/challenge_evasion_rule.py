from datetime import timedelta

from asgiref.sync import sync_to_async
from django.db.models import Sum
from django.utils import timezone
from devkit.message import Message

from core.audit.events import SIGNAL_EVENTS
from core.models.identity import IdentityObservation

from .base_rule import BaseRule, Maturity, RuleKind


# How long a failed challenge stays relevant to this merchant's own decisions.
WINDOW_DAYS = 30

# One failure is a typo. Two is a pattern.
FAILURE_LIMIT = 1


@sync_to_async
def _failures(identity_key_ids, application):
    total = (
        IdentityObservation.objects
        .filter(
            identity_key_id__in=identity_key_ids,
            application=application,
            last_seen_at__gte=timezone.now() - timedelta(days=WINDOW_DAYS),
        )
        .aggregate(failed=Sum("challenge_failed_count"))
    )

    return total["failed"] or 0


class ChallengeEvasionRule(BaseRule):
    """
    Flags an actor who has been asked to step up and did not clear it.

    This is the half of the challenge loop that makes a challenge worth
    issuing. A step-up that is merely abandoned teaches FLIT nothing unless
    the abandonment is remembered, and an actor who walks away from three
    challenges and comes back a fourth time is telling you what they are.

    Unlike NetworkReputationRule this reads only the merchant's own
    observations, so it needs no k-anonymity: nothing here came from anyone
    else.
    """

    kind = RuleKind.CORROBORATION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_challenges.py::TestTheLoopCloses"

    @property
    def applies(self):
        return (
            isinstance(self.event, SIGNAL_EVENTS)
            and self.scope.identity_ladder is not None
            and bool(self.scope.identity_ladder.network_key_ids())
        )

    async def perform(self):
        failures = await _failures(
            self.scope.identity_ladder.network_key_ids(), self.application,
        )

        if failures <= FAILURE_LIMIT:
            return None

        return Message(
            code="challenge_evasion",
            path="visit_id",
            text=f"This actor has failed or abandoned {failures} challenges",
            context=dict(
                failures=failures,
                window_days=WINDOW_DAYS,
                severity=round(min(0.5 + 0.1 * (failures - FAILURE_LIMIT), 0.9), 4),
            ),
        )
