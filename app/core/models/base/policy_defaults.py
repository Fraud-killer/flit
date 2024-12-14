device_validity_days = 90

aml_cft_limit="NGN 5,000,000.00"


kyc_level_limits = {
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
