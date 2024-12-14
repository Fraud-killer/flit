from devkit import undefined


class TransactionEvent:
    def __init__(self, **kwargs):
        self.txn_id = kwargs.get("txn_id", undefined)
        self.txn_type = kwargs.get("txn_type", undefined)
        self.txn_amount = kwargs.get("txn_amount", undefined)
        self.txn_instrument = kwargs.get("txn_instrument", undefined)

        self.kyc_level = kwargs.get("kyc_level", undefined)
        self.client_id = kwargs.get("client_id", undefined)

        self.current_cumulative_balance = kwargs.get(
            "current_cumulative_balance",
            undefined,
        )

        self.daily_cumulative_debit_balance = kwargs.get(
            "daily_cumulative_debit_balance",
            undefined,
        )

        self.device_query_id = kwargs.get("device_query_id", undefined)

    def verify(self): return list()  # TODO: Complete this implementations
