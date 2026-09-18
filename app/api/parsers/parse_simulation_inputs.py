from devkit import undefined
from devkit.struct import Struct
from devkit.messages import msg_dict, msg_void_or_decimal

from .parse_application_id import parse_application_id


MAX_DAYS = 365


def parse_simulation_inputs(id, request):
    weights = request.data.get("weights", undefined)
    thresholds = request.data.get("thresholds", undefined)
    days = request.data.get("days", undefined)

    errors = list()
    application = parse_application_id(id, errors)

    if weights is not undefined and not is_weight_map(weights):
        errors.append(msg_dict.new(path="weights", context=dict(values="numbers between 0 and 1")))

    if thresholds is not undefined and not is_threshold_map(thresholds):
        errors.append(msg_dict.new(path="thresholds", context=dict(keys=["block_at", "review_at"])))

    if days is not undefined and not is_window(days):
        errors.append(msg_void_or_decimal.new(path="days", context=dict(maximum=MAX_DAYS)))

    data = None if errors else (
        Struct(
            application=application,
            days=30 if days is undefined else int(days),
            weights=None if weights is undefined else weights,
            thresholds=None if thresholds is undefined else thresholds,
        )
    )

    return (data, errors)


def is_ratio(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1


def is_weight_map(value):
    return (
        isinstance(value, dict)
        and all(isinstance(code, str) and is_ratio(weight) for code, weight in value.items())
    )


def is_threshold_map(value):
    return (
        isinstance(value, dict)
        and set(value).issubset({"block_at", "review_at"})
        and all(is_ratio(threshold) for threshold in value.values())
    )


def is_window(value):
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_DAYS
