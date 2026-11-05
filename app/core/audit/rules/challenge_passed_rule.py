"""
A challenge that was cleared buys something.

Until now a passed challenge was written to the identity graph and never
read: an actor who proved they were a person was treated, on the next event,
exactly like one who had not. That makes the step-up a tax with no receipt.
This rule reads recent passes on the actor's keys and tells the engine, which
waives the challenge it would have asked for again and discounts the score.

It is corroboration, not absolution. A hard block ignores it, and so does a
control that could not run; it answers the question "should this actor be
challenged?", not "is this actor honest?".
"""

from datetime import timedelta

from asgiref.sync import sync_to_async
from django.db.models import Sum
from django.utils import timezone
from devkit.message import Message

from core.audit.events import SIGNAL_EVENTS
from core.models.identity import IdentityObservation

from .base_rule import BaseRule, Maturity, RuleKind


# A pass is worth something for this long. Long enough to cover a session,
# short enough that a device that changed hands is challenged again.
WINDOW_HOURS = 24


@sync_to_async
def _passes(identity_key_ids, application):
    total = (
        IdentityObservation.objects
        .filter(
            identity_key_id__in=identity_key_ids,
            application=application,
            last_seen_at__gte=timezone.now() - timedelta(hours=WINDOW_HOURS),
        )
        .aggregate(passed=Sum("challenge_passed_count"), failed=Sum("challenge_failed_count"))
    )
    return total["passed"] or 0, total["failed"] or 0


class ChallengePassedRule(BaseRule):

    kind = RuleKind.CORROBORATION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_challenge_replay.py::TestChallengePassedRule"

    @property
    def applies(self):
        return (
            isinstance(self.event, SIGNAL_EVENTS)
            and self.scope.identity_ladder is not None
            and bool(self.scope.identity_ladder.network_key_ids())
        )

    async def perform(self):
        passed, failed = await _passes(
            self.scope.identity_ladder.network_key_ids(), self.application,
        )

        # A pass after failures is a pass; failures after a pass are not.
        if passed < 1 or failed > passed:
            return None

        return Message(
            code="recent_challenge_passed",
            path="visit_id",
            text=f"This actor cleared a step-up in the last {WINDOW_HOURS} hours",
            context=dict(
                passed=passed,
                failed=failed,
                window_hours=WINDOW_HOURS,
                score=0.0,
                # Read by the engine: waive the challenge, discount the score.
                passed_challenge=True,
            ),
        )
