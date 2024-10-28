from core.money import Money

from .base_rule import BaseRule


class KycMaxCummulativeBalanceExceededRule(BaseRule):
    async def exert(self):
        txn_type = self.data["txn_type"]
        amount = Money(self.data["txn_amount"])

        if txn_type != "credit": return None

        messages = list()

        if "kyc_level" not in self.data:
            messages.append("KYC level was not provided")
        elif self.data["kyc_level"] is None:
            messages.append("KYC level was found to be null")

        if "current_cumulative_balance" not in self.data:
            messages.append("Current cumulative balance was not provided")
        elif self.data["current_cumulative_balance"] is None:
            messages.append("Current cumulative balance was found to be null")

        if messages: return messages

        kyc_level = self.data["kyc_level"]
        current_cumulative_balance = Money(self.data["current_cumulative_balance"])
        maximum_cumulative_balance = self.policy.kyc_level_limits[kyc_level]["maximum_cumulative_balance"]
        maximum_cumulative_balance = None if maximum_cumulative_balance is None else Money(maximum_cumulative_balance)

        if maximum_cumulative_balance is None: return None

        new_balance = amount + current_cumulative_balance

        if new_balance <= maximum_cumulative_balance: return None

        return ["Maximum cummulative balance exceeded"]
