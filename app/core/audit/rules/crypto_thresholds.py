"""
Limits for the crypto rules.

Crypto fintechs differ enormously in shape — an exchange, a card issuer with
stablecoin funding and a remittance app have nothing in common in these
numbers — so every one of them is a policy override away from being wrong.
"""

DEFAULT_CRYPTO_THRESHOLDS = {
    # CryptoCashOutRule: value arriving and leaving on a chain shortly after.
    "cash_out_minutes": 60,
    "cash_out_ratio": 0.8,

    # CollectionWalletRule: distinct accounts of one merchant paying into one
    # address. Deliberately not 2: a family, a couple of colleagues or two
    # accounts of the same person legitimately share a destination, and an
    # exchange deposit address can be reused by a customer across accounts.
    "accounts_per_destination": 4,
    "destination_window_days": 30,

    # NewWithdrawalAddressRule: how much prior withdrawal history an account
    # needs before a new destination means anything. With none, the first
    # withdrawal is simply the first withdrawal.
    "min_prior_withdrawals": 2,
}


def get_crypto_thresholds(policy):
    overrides = getattr(policy, "crypto_thresholds", None) or {}
    return {**DEFAULT_CRYPTO_THRESHOLDS, **overrides}
