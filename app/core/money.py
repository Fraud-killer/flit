import re
from moneyed import Money
from devkit import execute
from decimal import Decimal
from babel.numbers import format_currency


MONEY_MAJOR_VALUE_REGEX = r"([1-9]\d{0,2}(?:\d*|(?:\,\d{3})*))"
MONEY_VALUE_REGEX = fr"{MONEY_MAJOR_VALUE_REGEX}(?:\.(\d{{2}}))?"
MONEY_PATTERN = re.compile(fr"([A-Z]{{3}})\s?{MONEY_VALUE_REGEX}")


class MoneyFormatError(Exception):
    pass


def init_money(formatted):
    match = (
        MONEY_PATTERN.fullmatch(formatted)
        if isinstance(formatted, str)
        else None
    )

    if not match:
        raise MoneyFormatError(repr(formatted))

    currency_code = match.group(1)
    minor_value = str(match.group(3) or 0)
    major_value = match.group(2).replace(",", "")
    value = Decimal(f"{major_value}.{minor_value}")

    return Money(value, currency_code)


def is_money(formatted):
    return not execute(init_money, formatted)[1]


def format_money(money):
    amount = money.amount
    currency = money.currency.code
    return format_currency(amount, currency, locale="en_US")


def is_currency_code(value):
    return True
