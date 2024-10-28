from core.money import Money

from .base_rule import BaseRule


class AmlCftLimitExceededRule(BaseRule):
    async def exert(self):
        amount = Money(self.data["txn_amount"])
        aml_cft_limit = Money(self.policy.aml_cft_limit["value"])

        if amount <= aml_cft_limit: return None

        return ["AML CFT Limit exceeded"]
