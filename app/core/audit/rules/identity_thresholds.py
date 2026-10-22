"""
Per-key limits for the correlation rules.

A weaker key needs a higher limit before it means anything: one device with
four accounts on it is a farm, one office IP with four accounts behind it is
a Tuesday. Setting the limits per key type is what lets the rules keep
speaking when there is no device fingerprint without drowning in noise.
"""

from core.identity_keys import IdentityKeyType as Key


# Keys that must never be used to count accounts. A consumer ISP's ASN
# carries every real signup in a market — counting on it would flag an entire
# country. The ASN rung stays on the ladder for reputation and coverage; it is
# just not a correlation key.
# A counterparty address is here for the same reason, from the other side: it
# is recorded so CollectionWalletRule can count the accounts paying into one
# address, but it never identifies the sender.
NON_CORRELATING_KEYS = {Key.ASN, Key.COUNTERPARTY}


DEFAULT_IDENTITY_THRESHOLDS = {
    # AccountFarmingRule: accounts first seen on one key within a day.
    "new_accounts_per_day": {
        Key.DEVICE: 3,
        Key.SIGNATURE: 4,
        # A person may legitimately fund two accounts from one wallet; ten in
        # a day is a farm paying for its own signups.
        Key.WALLET: 2,
        Key.EMAIL_ROOT: 2,
        # Deliberately generous: carrier-grade NAT puts a whole mobile market
        # behind a handful of addresses, and an IP breach alone is scored at
        # half confidence precisely because it is weak evidence on its own.
        Key.IP: 8,
    },
    # MultiAccountingRule: distinct accounts active on one key in the window.
    "max_accounts": {
        Key.DEVICE: 3,
        Key.SIGNATURE: 4,
        Key.WALLET: 3,
        Key.EMAIL_ROOT: 2,
        Key.IP: 15,
    },
    "accounts_window_days": 30,
}


def get_identity_thresholds(policy):
    """
    Policy overrides, merged one level deep so an application can retune a
    single key without restating the whole table.
    """
    overrides = getattr(policy, "identity_thresholds", None) or {}
    merged = {
        key: (dict(value) if isinstance(value, dict) else value)
        for key, value in DEFAULT_IDENTITY_THRESHOLDS.items()
    }

    for name, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(name), dict):
            merged[name].update(value)
        else:
            merged[name] = value

    # The device rung predates the ladder. Honour the older policy fields so
    # an application that tuned them keeps the behaviour it configured.
    legacy_mule = getattr(policy, "mule_thresholds", None) or {}
    if "new_accounts_per_device_per_day" in legacy_mule:
        merged["new_accounts_per_day"][Key.DEVICE] = legacy_mule[
            "new_accounts_per_device_per_day"
        ]

    legacy_device = getattr(policy, "device_thresholds", None) or {}
    if "max_accounts_per_device" in legacy_device:
        merged["max_accounts"][Key.DEVICE] = legacy_device["max_accounts_per_device"]
    if "accounts_per_device_window_days" in legacy_device:
        merged["accounts_window_days"] = legacy_device["accounts_per_device_window_days"]

    return merged


def limit_for(thresholds, name, key_type):
    table = thresholds.get(name) or {}
    if isinstance(table, dict):
        return table.get(key_type)
    return table
