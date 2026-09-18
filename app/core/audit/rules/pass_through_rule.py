from devkit.message import Message
from core.audit.events import TransactionEvent

from .base_rule import BaseRule
from .mule_thresholds import get_mule_thresholds


class PassThroughRule(BaseRule):
    """
    Flags an account that pays out what it just received.

    A mule account is a waypoint, not a destination: funds arrive and leave
    almost immediately, and close to in full. Ordinary customers accumulate,
    spend part of a balance, and do not time withdrawals to arrivals.
    """

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and self.event.type == "debit"
            and self.event.account_id is not None
            and self.scope.account_activity is not None
        )

    async def perform(self):
        thresholds = get_mule_thresholds(self.policy)
        activity = self.scope.account_activity

        credits = activity.credits_since_last_debit()

        if len(credits) < thresholds["min_pass_through_credits"]:
            return None

        window_minutes = thresholds["pass_through_minutes"]
        recent = [
            credit for credit in credits
            if (activity.now - credit["timestamp"]).total_seconds() <= window_minutes * 60
        ]

        received = activity.total(recent)
        amount = self.event.amount

        if not received or not isinstance(amount, (int, float)):
            return None

        ratio = amount / received

        if ratio < thresholds["pass_through_ratio"]:
            return None

        minutes_held = min(
            (activity.now - credit["timestamp"]).total_seconds() / 60
            for credit in recent
        )

        return Message(
            code="pass_through_funds",
            path="amount",
            text=(
                f"Account is paying out {ratio:.0%} of funds received "
                f"in the last {window_minutes} minutes"
            ),
            context=dict(
                ratio=round(ratio, 4),
                received=received,
                paid_out=amount,
                credits=len(recent),
                minutes_held=round(minutes_held, 1),
                score=min(0.6 + 0.1 * len(recent), 0.95),
            ),
        )
