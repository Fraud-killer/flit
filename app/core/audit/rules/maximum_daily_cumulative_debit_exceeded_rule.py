from devkit.message import Message
from core.money import Money, init_money
from core.audit.events import TransactionEvent

from .base_rule import BaseRule


class MaximumDailyCumulativeDebitExceededRule(BaseRule):
    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and self.event.type == "debit"
        )

    async def perform(self):
        self.ensure_present(dict(
            amount=self.event.amount,
            kyc_level=self.event.kyc_level,
            currency_code=self.event.currency_code,
            daily_cumulative_debit_balance=self.event.daily_cumulative_debit_balance,
        ))

        amount = Money(
            self.event.amount,
            self.event.currency_code,
        )

        daily_cumulative_debit_balance = Money(
            self.event.daily_cumulative_debit_balance,
            self.event.currency_code,
        )

        kyc_level_limits = self.policy.kyc_level_limits
        level_limits = kyc_level_limits[self.event.kyc_level]
        raw_maximum_daily_cumulative_debit = level_limits["maximum_daily_cumulative_debit"]

        maximum_daily_cumulative_debit = (
            None
            if raw_maximum_daily_cumulative_debit is None
            else init_money(raw_maximum_daily_cumulative_debit)
        )

        if not maximum_daily_cumulative_debit: return None

        new_daily_cumulative_debit_balance = amount + daily_cumulative_debit_balance

        if new_daily_cumulative_debit_balance > maximum_daily_cumulative_debit:
            return (
                Message(
                    code="maximum_daily_cumulative_debit_exceeded",
                    path="amount",
                    context=dict(maximum_daily_cumulative_debit=raw_maximum_daily_cumulative_debit),
                    text="New daily cumulative debit balance exceeds the maximum specified in your policy",
                )
            )
