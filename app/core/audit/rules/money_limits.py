from devkit.message import Message


def currency_mismatch(amount, limit, *, path="currency_code"):
    """
    A policy limit can only be compared with an amount in the same currency.
    Comparing across currencies raises in py-moneyed, so rules report the
    misconfiguration instead of failing the whole audit.
    """
    if limit is None or amount.currency == limit.currency:
        return None

    return Message(
        code="policy_currency_mismatch",
        path=path,
        text="Transaction currency does not match the limit currency in your policy",
        context=dict(
            amount_currency=str(amount.currency),
            limit_currency=str(limit.currency),
            score=0.0,
        ),
    )
