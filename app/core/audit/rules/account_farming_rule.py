from datetime import timedelta
from django.utils import timezone
from devkit.message import Message
from core.audit.events import SIGNAL_EVENTS

from .base_rule import BaseRule, Maturity, RuleKind
from .identity_thresholds import get_identity_thresholds
from .identity_correlation import code_for, correlating_rungs, severity_for, strongest_breach


class AccountFarmingRule(BaseRule):
    """
    Flags an actor creating accounts in bulk.

    MultiAccountingRule counts accounts an actor has ever used, which a shared
    family laptop trips honestly. This counts accounts *first seen* within a
    day, which is what an account farm looks like.

    Correlation walks the identity ladder rather than requiring a device. An
    attacker who never runs our JavaScript produces no device fingerprint, and
    this rule used to switch itself off for exactly that actor; it now falls
    back to the strongest key it does have, and names that key in the finding
    so a reviewer knows how much to trust it.
    """

    techniques = ("T1585",)
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = (
        "tests/unit/test_mule_detection.py::TestAccountFarmingRule; "
        "tests/unit/test_signup_defence.py::TestIdentityLadder"
    )

    @property
    def applies(self):
        return (
            isinstance(self.event, SIGNAL_EVENTS)
            and bool(correlating_rungs(self.scope.identity_ladder))
        )

    async def perform(self):
        thresholds = get_identity_thresholds(self.policy)

        breach = await strongest_breach(
            self,
            thresholds=thresholds,
            limit_name="new_accounts_per_day",
            field="first_seen_at",
            since=timezone.now() - timedelta(days=1),
        )

        if breach is None:
            return None

        rung, count, limit = breach

        return Message(
            code=code_for("account_farming", rung),
            path="visit_id",
            text=(
                f"{count} accounts were first seen on this "
                f"{rung.key_type} within a day"
            ),
            context=dict(
                new_accounts=count,
                limit=limit,
                key_type=rung.key_type,
                key_confidence=rung.confidence,
                identity_key_id=str(rung.key.id),
                severity=severity_for(count, limit),
            ),
        )
