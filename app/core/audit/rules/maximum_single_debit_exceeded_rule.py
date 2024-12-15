from devkit.message import Message
from core.money import Money, init_money
from core.audit.events import TransactionEvent

from .base_rule import BaseRule


class MaximumSingleDebitExceededRule(BaseRule):
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
        ))

        amount = Money(
            self.event.amount,
            self.event.currency_code,
        )

        kyc_level_limits = self.policy.kyc_level_limits
        level_limits = kyc_level_limits[self.event.kyc_level]
        raw_maximum_single_debit = level_limits["maximum_single_debit"]

        maximum_single_debit = (
            None
            if raw_maximum_single_debit is None
            else init_money(raw_maximum_single_debit)
        )

        if maximum_single_debit and amount > maximum_single_debit:
            return (
                Message(
                    code="maximum_single_debit_exceeded",
                    path="amount",
                    context=dict(maximum_single_debit=raw_maximum_single_debit),
                    text="Amount exceeds the maximum single debit specified in your policy",
                )
            )
