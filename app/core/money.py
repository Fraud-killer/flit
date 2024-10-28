from re import compile
from decimal import Decimal


class MoneyError(Exception):
    pass


class Money:
    PATTERN = compile(r"([A-Z]{3})\s(\d{1,3}(?:\d*?|(?:\,\d{3})*))(?:\.(\d{1,2}))?")

    def __init__(self, argument):
        match = (
            self.PATTERN.fullmatch(argument)
            if isinstance(argument, str)
            else None
        )

        if match is None:
            raise MoneyError(f"FormatError: {repr(argument)}")

        self.currency_code = match.group(1)
        self.minor_value = int(match.group(3) or 0)
        self.major_value = int(match.group(2).replace(",", ""))
        self.value = Decimal(f"{self.major_value}.{self.minor_value}")

    def __str__(self):
        value_string = f"{self.major_value:,}.{self.minor_value:02}"
        return f"{self.currency_code} {value_string}"

    def __repr__(self):
        return f"<Money value={str(self)}>"

    def __eq__(self, other):
        self.__ensure_same_currency_code(other)
        return self.value == other.value

    def __lt__(self, other):
        self.__ensure_same_currency_code(other)
        return self.value < other.value

    def __le__(self, other):
        self.__ensure_same_currency_code(other)
        return self.value <= other.value

    def __gt__(self, other):
        self.__ensure_same_currency_code(other)
        return self.value > other.value
    
    def __ge__(self, other):
        self.__ensure_same_currency_code(other)
        return self.value >= other.value

    def __add__(self, other):
        self.__ensure_same_currency_code(other)
        new_value = self.value + other.value
        return Money(f"{self.currency_code} {new_value}")

    def __sub__(self, other):
        self.__ensure_same_currency_code(other)
        new_value = self.value - other.value
        return Money(f"{self.currency_code} {new_value}")

    def __ensure_same_currency_code(self, other):
        if self.currency_code == other.currency_code: return
        postfix = f"{self.currency_code}, {other.currency_code}"
        raise MoneyError(f"CurrencyCodeMismatchError: {postfix}")
