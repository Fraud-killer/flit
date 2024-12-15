from devkit.message import Message
from core.money import Money, init_money
from core.audit.events import TransactionEvent

from core.audit.rules.base_rule import BaseRule


class AmlCftLimitExceededRule(BaseRule):
    @property
    def applies(self):
        return isinstance(self.event, TransactionEvent)

    async def perform(self):
        self.ensure_present(dict(
            amount=self.event.amount,
            currency_code=self.event.currency_code,
        ))

        amount = Money(
            self.event.amount,
            self.event.currency_code,
        )

        raw_aml_cft_limit = self.policy.aml_cft_limit

        aml_cft_limit = (
            None
            if raw_aml_cft_limit is None
            else init_money(raw_aml_cft_limit)
        )

        if amount > aml_cft_limit:
            return (
                Message(
                    code="aml_cft_limit_exceeded",
                    path="amount",
                    context=dict(aml_cft_limit=raw_aml_cft_limit),
                    text="Amount exceeds the AML/CFT limit specified in your policy",
                )
            )
