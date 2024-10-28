from core.money import Money
from bootkit.mezage import Mezage

from bootkit.mezages import (
    mzg_mapping,
    mzg_req_prop,
    mzg_in_choices,
    mzg_dense_string,
    mzg_opt_null_or_dense_string,
)

from bootkit import execute, undefined
from bootkit.checks import is_dense_string
from core.mezages import mzg_money, mzg_opt_null_or_money


def validate_end_user_audit_data(data, policy):
    if not isinstance(data, dict): return [mzg_mapping.new()]

    end_user_id = data.get("end_user_id", undefined)
    device_query_id = data.get("device_query_id", None)

    errors = list()

    if end_user_id is undefined:
        errors.append(
            mzg_req_prop.new(target="end_user_id")
        )
    elif not is_dense_string(end_user_id):
        errors.append(
            mzg_dense_string.new(target="end_user_id")
        )

    if device_query_id is not None and not is_dense_string(device_query_id):
        errors.append(
            mzg_opt_null_or_dense_string.new(target="device_query_id")
        )
    
    return errors


def validate_transaction_audit_data(data, policy):
    if not isinstance(data, dict): return [mzg_mapping.new()]

    txn_id = data.get("txn_id", undefined)
    txn_type = data.get("txn_type", undefined)
    txn_amount = data.get("txn_amount", undefined)
    end_user_id = data.get("end_user_id", undefined)
    txn_instrument = data.get("txn_instrument", undefined)

    kyc_level = data.get("kyc_level", None)    
    device_query_id = data.get("device_query_id", None)
    current_cumulative_balance = data.get("current_cumulative_balance", None)
    daily_cumulative_debit_balance = data.get("daily_cumulative_debit_balance", None)

    errors = list()

    if txn_id is undefined:
        errors.append(
            mzg_req_prop.new(target="txn_id")
        )
    elif not is_dense_string(txn_id):
        errors.append(
            mzg_dense_string.new(target="txn_id")
        )

    if txn_type is undefined:
        errors.append(
            mzg_req_prop.new(target="txn_type")
        )
    elif txn_type not in ("credit", "debit"):
        errors.append(
            mzg_in_choices.new(target="txn_type", context=dict(choices=["credit", "debit"]))
        )

    if txn_amount is undefined:
        errors.append(
            mzg_req_prop.new(target="txn_amount")
        )
    elif execute(Money, txn_amount)[1]:
        errors.append(
            mzg_money.new(target="txn_amount")
        )

    if txn_instrument is undefined:
        errors.append(
            mzg_req_prop.new(target="txn_instrument")
        )
    elif txn_instrument != "account":
        errors.append(
            mzg_in_choices.new(target="txn_instrument", context=dict(choices=["account"]))
        )

    if kyc_level is not None and (not policy or kyc_level not in policy.kyc_level_limits):
        if policy:
            errors.append(
                mzg_in_choices.new(target="kyc_level", context=dict(choices=list(policy.kyc_level_limits.keys())))
            )
        else:
            errors.append(Mezage(code="kyc_level", text="Kyc level could not be validated").new(target="kyc_level"))

    if end_user_id is undefined:
        errors.append(
            mzg_req_prop.new(target="end_user_id")
        )
    elif not is_dense_string(end_user_id):
        errors.append(
            mzg_dense_string.new(target="end_user_id")
        )

    if device_query_id is not None and not is_dense_string(device_query_id):
        errors.append(
            mzg_opt_null_or_dense_string.new(target="device_query_id")
        )
    
    if current_cumulative_balance is not None and execute(Money, current_cumulative_balance)[1]:
        errors.append(
            mzg_opt_null_or_money.new(target="current_cumulative_balance")
        )

    if daily_cumulative_debit_balance is not None and execute(Money, daily_cumulative_debit_balance)[1]:
        errors.append(
            mzg_opt_null_or_money.new(target="daily_cumulative_debit_balance")
        )

    return errors
