from devkit.message import Message


msg_money = (
    Message(
        code="money",
        text="Must match the money format",
    )
)


msg_currency_code = (
    Message(
        code="currency_code",
        text="Must be a valid currency code",
    )
)


msg_null_or_money = (
    Message(
        code="null_or_money",
        text="Must be null or match the money format",
    )
)


msg_not_present_or_money = (
    Message(
        code="not_present_or_money",
        text="Optional, otherwise must be null or match the money format",
    )
)
