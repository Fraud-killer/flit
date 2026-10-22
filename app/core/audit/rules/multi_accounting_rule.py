from datetime import timedelta
from django.utils import timezone
from devkit.message import Message
from core.audit.events import SIGNAL_EVENTS

from .base_rule import BaseRule, Maturity, RuleKind
from .identity_thresholds import get_identity_thresholds
from .identity_correlation import code_for, correlating_rungs, severity_for, strongest_breach


class MultiAccountingRule(BaseRule):
    """
    Flags an actor holding more accounts than the policy allows.

    Like AccountFarmingRule, this walks the identity ladder: a device match is
    reported at full confidence, and the same shape seen only on a shared IP
    is reported as the weaker evidence it is.
    """

    techniques = ("T1585",)
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = (
        "tests/unit/test_device_graph.py::TestMultiAccountingRule; "
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
        window_days = thresholds["accounts_window_days"]

        breach = await strongest_breach(
            self,
            thresholds=thresholds,
            limit_name="max_accounts",
            field="last_seen_at",
            since=timezone.now() - timedelta(days=window_days),
        )

        if breach is None:
            return None

        rung, count, limit = breach

        return Message(
            code=code_for("multi_accounting", rung),
            path="visit_id",
            text=(
                f"This {rung.key_type} is used by {count} accounts "
                f"in {window_days} days"
            ),
            context=dict(
                accounts=count,
                limit=limit,
                window_days=window_days,
                key_type=rung.key_type,
                key_confidence=rung.confidence,
                identity_key_id=str(rung.key.id),
                severity=severity_for(count, limit, base=0.6),
            ),
        )
