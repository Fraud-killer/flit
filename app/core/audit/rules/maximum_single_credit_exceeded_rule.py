from devkit.message import Message
from core.money import Money, init_money
from core.audit.events import TransactionEvent

from .base_rule import BaseRule


class MaximumSingleCreditExceededRule(BaseRule):
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
        ))

        amount = Money(
            self.event.amount,
            self.event.currency_code,
        )

        kyc_level_limits = self.policy.kyc_level_limits
        level_limits = kyc_level_limits[self.event.kyc_level]
        raw_maximum_single_credit = level_limits["maximum_single_credit"]

        maximum_single_credit = (
            None
            if raw_maximum_single_credit is None
            else init_money(raw_maximum_single_credit)
        )

        if maximum_single_credit and amount > maximum_single_credit:
            return (
                Message(
                    code="maximum_single_credit_exceeded",
                    path="amount",
                    context=dict(maximum_single_credit=raw_maximum_single_credit),
                    text="Amount exceeds the maximum single credit specified in your policy",
                )
            )
