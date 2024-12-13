from core.money import Money
from devkit.message import Message
from audit.events import TransactionEvent

from .base_rule import BaseRule


class AmlCftLimitExceededRule(BaseRule):
    @property
    def applies(self):
        return isinstance(self.scope.event, TransactionEvent)

    async def perform(self):
        txn_amount = Money(self.scope.event.txn_amount)
        raw_aml_cft_limit = self.scope.policy.aml_cft_limit["value"]

        aml_cft_limit = (
            None
            if raw_aml_cft_limit is None
            else Money(raw_aml_cft_limit)
        )

        if txn_amount > aml_cft_limit:
            return (
                # TODO: Refine the below message for reuse
                Message(
                    code="aml_cft_limit_exceeded",
                    context=dict(limit=raw_aml_cft_limit),
                    text="Some texts that will be refined goes here",
                )
            )
