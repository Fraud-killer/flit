from core.money import Money

from .base_rule import BaseRule


class KycMaxDailyCummulativeDebitExceededRule(BaseRule):
    async def exert(self):
        txn_type = self.data["txn_type"]
        amount = Money(self.data["txn_amount"])

        if txn_type != "debit": return None

        messages = list()

        if "kyc_level" not in self.data:
            messages.append("KYC level was not provided")
        elif self.data["kyc_level"] is None:
            messages.append("KYC level was found to be null")

        if "daily_cumulative_debit_balance" not in self.data:
            messages.append("Daily cumulative debit balance was not provided")
        elif self.data["daily_cumulative_debit_balance"] is None:
            messages.append("Daily cumulative debit balance was found to be null")

        if messages: return messages

        kyc_level = self.data["kyc_level"]
        daily_cumulative_debit_balance = Money(self.data["daily_cumulative_debit_balance"])
        maximum_daily_cumulative_debit = self.policy.kyc_level_limits[kyc_level]["maximum_daily_cumulative_debit"]
        maximum_daily_cumulative_debit = None if maximum_daily_cumulative_debit is None else Money(maximum_daily_cumulative_debit)

        if maximum_daily_cumulative_debit is None: return None

        new_balance = amount + daily_cumulative_debit_balance

        if new_balance <= maximum_daily_cumulative_debit: return None

        return ["Maximum daily cummulative debit exceeded"]

