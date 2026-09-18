DEFAULT_MULE_THRESHOLDS = {
    # PassThroughRule: money in, straight back out
    "pass_through_ratio": 0.8,          # share of recent credits paid out
    "pass_through_minutes": 60,         # how quickly it left
    "min_pass_through_credits": 1,

    # StructuringRule: many small credits from many senders
    "unique_payers_per_day": 5,
    "structured_credits_per_day": 8,

    # DormantAwakeningRule: a quiet account that suddenly moves money
    "dormant_days": 60,
    "dormant_wake_amount_ratio": 2.0,   # versus its own historical average

    # AccountFarmingRule: accounts created in bulk on one device
    "new_accounts_per_device_per_day": 3,

    # MuleNetworkRule: accounts on this device already confirmed fraudulent
    "confirmed_fraud_accounts_per_device": 1,
}


def get_mule_thresholds(policy):
    overrides = getattr(policy, "mule_thresholds", None) or {}
    return {**DEFAULT_MULE_THRESHOLDS, **overrides}
