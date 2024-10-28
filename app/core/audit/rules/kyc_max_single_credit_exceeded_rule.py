from core.money import Money

from .base_rule import BaseRule


class KycMaxSingleCreditExceededRule(BaseRule):
    async def exert(self):
        txn_type = self.data["txn_type"]
        amount = Money(self.data["txn_amount"])

        if txn_type != "credit": return None

        messages = list()

        if "kyc_level" not in self.data:
            messages.append("KYC level was not provided")
        elif self.data["kyc_level"] is None:
            messages.append("KYC level was found to be null")

        if messages: return messages

        kyc_level = self.data["kyc_level"]
        maximum_single_credit = self.policy.kyc_level_limits[kyc_level]["maximum_single_credit"]
        maximum_single_credit = None if maximum_single_credit is None else Money(maximum_single_credit)

        if maximum_single_credit is None or amount <= maximum_single_credit:
            return None

        return ["Maximum single credit exceeded"]
