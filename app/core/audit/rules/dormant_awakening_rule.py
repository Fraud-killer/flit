from devkit.message import Message
from core.audit.events import TransactionEvent

from .base_rule import BaseRule
from .mule_thresholds import get_mule_thresholds


class DormantAwakeningRule(BaseRule):
    """
    Flags a long-quiet account that suddenly moves money.

    Bought, farmed and taken-over accounts share this shape: months of
    silence, then activity that does not resemble the account's own past.
    """

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and self.event.account_id is not None
            and self.scope.account_activity is not None
        )

    async def perform(self):
        thresholds = get_mule_thresholds(self.policy)
        activity = self.scope.account_activity

        dormant_days = activity.dormant_days()

        if dormant_days is None or dormant_days < thresholds["dormant_days"]:
            return None

        amount = self.event.amount
        history = [event for event in activity.events if event["amount"]]
        average = activity.total(history) / len(history) if history else 0

        unusual = (
            isinstance(amount, (int, float))
            and average
            and amount / average >= thresholds["dormant_wake_amount_ratio"]
        )

        return Message(
            code="dormant_account_activity",
            path="client_id",
            text=f"Account was inactive for {int(dormant_days)} days before this transaction",
            context=dict(
                dormant_days=int(dormant_days),
                average_amount=round(average, 2) if average else None,
                amount=amount,
                unusual_amount=bool(unusual),
                score=0.75 if unusual else 0.5,
            ),
        )
