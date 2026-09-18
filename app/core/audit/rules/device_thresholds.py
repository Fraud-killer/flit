from datetime import timedelta


DEFAULT_DEVICE_THRESHOLDS = {
    # MultiAccountingRule: distinct accounts on one device
    "max_accounts_per_device": 3,
    "accounts_per_device_window_days": 30,
    # AccountSharingRule: distinct devices on one account
    "max_devices_per_account_per_day": 3,
    "max_devices_per_account_per_hour": 2,
}


def get_device_thresholds(policy):
    overrides = getattr(policy, "device_thresholds", None) or {}
    return {**DEFAULT_DEVICE_THRESHOLDS, **overrides}


def scaled_score(count, limit, base=0.5, step=0.1, cap=0.95):
    """Grows with how far `count` is past `limit`."""
    return min(base + step * (count - limit), cap)


DAY = timedelta(days=1)
HOUR = timedelta(hours=1)
