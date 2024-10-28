from core.money import Money

from .base_rule import BaseRule


class KycMaxSingleDebitExceededRule(BaseRule):
    async def exert(self):
        txn_type = self.data["txn_type"]
        amount = Money(self.data["txn_amount"])

        if txn_type != "debit": return None

        messages = list()

        if "kyc_level" not in self.data:
            messages.append("KYC level was not provided")
        elif self.data["kyc_level"] is None:
            messages.append("KYC level was found to be null")

        if messages: return messages

        kyc_level = self.data["kyc_level"]
        maximum_single_debit = self.policy.kyc_level_limits[kyc_level]["maximum_single_debit"]
        maximum_single_debit = None if maximum_single_debit is None else Money(maximum_single_debit)

        if maximum_single_debit is None or amount <= maximum_single_debit:
            return None

        return ["Maximum single debit exceeded"]

