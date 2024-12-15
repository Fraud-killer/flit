from devkit.message import Message
from core.money import Money, init_money
from core.audit.events import TransactionEvent

from .base_rule import BaseRule


class MaximumCumulativeBalanceExceededRule(BaseRule):
    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and self.event.type == "credit"
        )

    async def perform(self):
        self.ensure_present(dict(
            amount=self.event.amount,
            kyc_level=self.event.kyc_level,
            currency_code=self.event.currency_code,
            current_cumulative_balance=self.event.current_cumulative_balance,
        ))

        amount = Money(
            self.event.amount,
            self.event.currency_code,
        )

        current_cumulative_balance = Money(
            self.event.current_cumulative_balance,
            self.event.currency_code,
        )

        kyc_level_limits = self.policy.kyc_level_limits
        level_limits = kyc_level_limits[self.event.kyc_level]
        raw_maximum_cumulative_balance = level_limits["maximum_cumulative_balance"]

        maximum_cumulative_balance = (
            None
            if raw_maximum_cumulative_balance is None
            else init_money(raw_maximum_cumulative_balance)
        )

        if not maximum_cumulative_balance: return None

        new_current_cumulative_balance = amount + current_cumulative_balance

        if new_current_cumulative_balance > maximum_cumulative_balance:
            return (
                Message(
                    code="maximum_cumulative_balance_exceeded",
                    path="amount",
                    context=dict(maximum_cumulative_balance=raw_maximum_cumulative_balance),
                    text="New cumulative balance exceeds the maximum specified in your policy",
                )
            )
