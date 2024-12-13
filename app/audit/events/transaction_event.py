from devkit import undefined


class TransactionEvent:
    def __init__(self, **kwargs):
        self.txn_id = kwargs.get("txn_id", undefined)
        self.txn_type = kwargs.get("txn_type", undefined)

        self.client_cumulative_debit_balance = kwargs.get(
            "client_cumulative_debit_balance",
            undefined,
        )

        self.client_cumulative_credit_balance = kwargs.get(
            "client_cumulative_credit_balance",
            undefined,
        )

        self.client_id = kwargs.get("client_id", undefined)
        self.txn_amount = kwargs.get("txn_amount", undefined)
        self.txn_instrument = kwargs.get("txn_instrument", undefined)
        self.device_query_id = kwargs.get("device_query_id", undefined)
        self.client_kyc_level = kwargs.get("client_kyc_level", undefined)

    def validate(self): return list()  # TODO: Complete this implementation
