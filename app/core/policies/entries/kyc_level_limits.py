from bootkit import execute

from bootkit.mezages import (
    mzg_mapping,
    mzg_req_prop,
    mzg_unexpected_props,
    mzg_invalid_prop_names,
)

from core.money import Money
from bootkit.checks import is_var_string
from core.mezages import mzg_null_or_money


class KycLevelLimits:
    key = "kyc_level_limits"

    default = {
        "level_one": dict(
            maximum_single_debit="NGN 3,000.00",
            maximum_single_credit="NGN 50,000.00",
            maximum_cumulative_balance="NGN 300,000.00",
            maximum_daily_cumulative_debit="NGN 30,000.00"
        ),
        "level_two": dict(
            maximum_single_debit="NGN 10,000.00",
            maximum_single_credit="NGN 100,000.00",
            maximum_cumulative_balance="NGN 500,000.00",
            maximum_daily_cumulative_debit="NGN 100,000.00"
        ),
        "level_three": dict(
            maximum_single_debit="NGN 10,000,000.00",
            maximum_single_credit=None,
            maximum_cumulative_balance=None,
            maximum_daily_cumulative_debit="NGN 100,000,000.00"
        )
    }

    LIMITS_PROPS = {
        "maximum_single_debit",
        "maximum_single_credit",
        "maximum_cumulative_balance",
        "maximum_daily_cumulative_debit",
    }

    @classmethod
    def validate(cls, data):
        if not isinstance(data, dict):
            return [mzg_mapping.new()]

        invalid_prop_names = [
            prop_name
            for prop_name in data
            if not is_var_string(prop_name)
        ]

        if invalid_prop_names:
            return [
               mzg_invalid_prop_names.new(
                    context=dict(
                        invalid_prop_names=invalid_prop_names
                    )
                )
            ]

        errors = list()

        for key, limits in data.items():
            if not isinstance(limits, dict):
                errors.append(mzg_mapping.new(target=key))
                continue

            for limit_key in cls.LIMITS_PROPS:
                if limit_key not in limits:
                    errors.append(
                       mzg_req_prop.new(
                            target=f"{key}.{limit_key}"
                        )
                    )
                elif (
                    limits[limit_key] is not None
                    and execute(Money, limits[limit_key])[1]
                ):
                    errors.append(
                        mzg_null_or_money.new(
                            target=f"{key}.{limit_key}"
                        )
                    )

            unexpected_props = list(set(limits) - cls.LIMITS_PROPS)

            if unexpected_props:
                errors.append(
                    mzg_unexpected_props.new(
                        target=key,
                        context=dict(
                            unexpected_properties=unexpected_props
                        )
                    )
                )

        return errors
