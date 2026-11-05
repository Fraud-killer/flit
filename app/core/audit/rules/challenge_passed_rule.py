"""
A challenge that was cleared buys something, for the actor who cleared it.

Until now a passed challenge was written to the identity graph and never
read: an actor who proved they were a person was treated, on the next event,
exactly like one who had not. That makes the step-up a tax with no receipt.
This rule reads recent passes on the actor's own keys and tells the engine,
which waives the challenge it would have asked for again and discounts a
score below the block line.

Three limits, each closing a way an attacker would spend one pass:

- Only keys that belong to the actor count: the device, its signature, the
  normalised email, a wallet they control. Never the IP or the ASN. On a
  carrier network or a shared office one address is thousands of people, and
  a pass by one of them must not vouch for the rest.
- Any fraud confirmed, or any challenge failed, on those keys since voids the
  pass. A pass is a receipt for one moment, not a character reference.
- The engine never lets a pass move a score that already blocks (see
  RiskEngine.calculate_risk). A pass answers "should this actor be challenged
  again?", not "is this actor honest?".
"""

from datetime import timedelta

from asgiref.sync import sync_to_async
from django.db.models import Sum
from django.utils import timezone
from devkit.message import Message

from core.audit.events import SIGNAL_EVENTS
from core.identity_keys import IdentityKeyType
from core.models.identity import IdentityObservation

from .base_rule import BaseRule, Maturity, RuleKind


# A pass is worth something for this long. Long enough to cover a session,
# short enough that a device that changed hands is challenged again.
WINDOW_HOURS = 24

# The keys a pass may be read from: the ones that identify the actor rather
# than the network they are on.
ACTOR_KEY_TYPES = (
    IdentityKeyType.DEVICE, IdentityKeyType.SIGNATURE, IdentityKeyType.EMAIL_ROOT, IdentityKeyType.WALLET,
)


@sync_to_async
def _passes(identity_key_ids, application):
    """(passed, failed, fraud) on the actor's own keys within the window."""
    total = (
        IdentityObservation.objects
        .filter(
            identity_key_id__in=identity_key_ids,
            identity_key__key_type__in=ACTOR_KEY_TYPES,
            application=application,
            last_seen_at__gte=timezone.now() - timedelta(hours=WINDOW_HOURS),
        )
        .aggregate(
            passed=Sum("challenge_passed_count"),
            failed=Sum("challenge_failed_count"),
            fraud=Sum("fraud_count"),
        )
    )
    return total["passed"] or 0, total["failed"] or 0, total["fraud"] or 0


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
        passed, failed, fraud = await _passes(
            self.scope.identity_ladder.network_key_ids(), self.application,
        )

        # A pass is voided by any failure or any confirmed fraud on the same
        # actor since. The order cannot be read back from the counters, so
        # either one, at any time in the window, is enough.
        if passed < 1 or failed > 0 or fraud > 0:
            return None

        return Message(
            code="recent_challenge_passed",
            path="visit_id",
            text=f"This actor cleared a step-up in the last {WINDOW_HOURS} hours",
            context=dict(
                passed=passed,
                failed=failed,
                fraud=fraud,
                keys=list(ACTOR_KEY_TYPES),
                window_hours=WINDOW_HOURS,
                score=0.0,
                # Read by the engine: waive the challenge, discount the score.
                passed_challenge=True,
            ),
        )
