from devkit.messages import (
    msg_in_choices,
    msg_dense_string,
    msg_void_or_dense_string,
)

from core.models import Policy
from core.money import is_currency_code
from devkit.messages import msg_void_or_decimal
from devkit.checks import is_present, is_dense_str
from core.messages.monies import msg_currency_code

from .base_event import BaseEvent, EventError


class TransactionEvent(BaseEvent):
    attributes = [
        "id",
        "type",
        "amount",
        "visit_id",
        "kyc_level",
        "client_id",
        "currency_code",
        "current_cumulative_balance",
        "daily_cumulative_debit_balance",
    ]

    def verify(self, policy=None):
        if not isinstance(policy, Policy):
            raise EventError("Verify: Policy is required")

        errors = list()

        if not is_dense_str(self.id):
            errors.append(msg_dense_string.new(path="id"))

        if self.type not in ("debit", "credit"):
            context = dict(choices=["debit", "credit"])
            errors.append(msg_in_choices.new(path="type", context=context))

        if is_present(self.amount) and type(self.amount) not in (int, float):
            errors.append(msg_void_or_decimal.new(path="amount"))

        if (
            is_present(self.kyc_level)
            and self.kyc_level not in policy.kyc_level_limits
        ):
            context = dict(choices=list(policy.kyc_level_limits))
            errors.append(msg_in_choices.new(path="kyc_level", context=context))

        if (
            is_present(self.client_id)
            and not is_dense_str(self.client_id)
        ):
            errors.append(msg_void_or_dense_string.new(path="client_id"))
        
        if (
            is_present(self.currency_code)
            and not is_currency_code(self.currency_code)
        ):
            errors.append(msg_currency_code.new(path="currency_code"))

        if (
            is_present(self.visit_id)
            and not is_dense_str(self.visit_id)
        ):
            errors.append(msg_void_or_dense_string.new(path="visit_id"))

        if (
            is_present(self.current_cumulative_balance)
            and type(self.current_cumulative_balance) not in (int, float)
        ):
            errors.append(msg_void_or_decimal.new(path="current_cumulative_balance"))
        
        if (
            is_present(self.daily_cumulative_debit_balance)
            and type(self.daily_cumulative_debit_balance) not in (int, float)
        ):
            errors.append(msg_void_or_decimal.new(path="daily_cumulative_debit_balance"))

        return errors
