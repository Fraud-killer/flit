from devkit.message import Message
from core.audit.events import TransactionEvent

from .base_rule import BaseRule
from .mule_thresholds import get_mule_thresholds


class StructuringRule(BaseRule):
    """
    Flags an account collecting money from many different senders.

    Mule accounts aggregate: victims of a scam, or a herder splitting funds
    below a reporting threshold, pay into one account. Counterparties come
    from the optional `counterparty_id` on the event; without it this rule
    still counts credit volume.
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

        credits = activity.within(days=1, kind="credit")
        payers = activity.counterparties(credits)

        messages = []

        if len(payers) > thresholds["unique_payers_per_day"]:
            messages.append(Message(
                code="many_unique_payers",
                path="client_id",
                text=f"Account received money from {len(payers)} different senders in a day",
                context=dict(
                    payers=len(payers),
                    limit=thresholds["unique_payers_per_day"],
                    credits=len(credits),
                    score=min(0.6 + 0.05 * (len(payers) - thresholds["unique_payers_per_day"]), 0.95),
                ),
            ))

        elif len(credits) > thresholds["structured_credits_per_day"]:
            messages.append(Message(
                code="credit_structuring",
                path="client_id",
                text=f"Account received {len(credits)} separate credits in a day",
                context=dict(
                    credits=len(credits),
                    limit=thresholds["structured_credits_per_day"],
                    total=activity.total(credits),
                    score=0.55,
                ),
            ))

        return messages
