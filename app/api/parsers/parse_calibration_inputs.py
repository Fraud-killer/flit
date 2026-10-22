from devkit import undefined
from devkit.struct import Struct
from devkit.messages import msg_void_or_decimal, msg_bool

from core.calibration import Calibrator

from .parse_application_id import parse_application_id


MAX_DAYS = 365


def parse_calibration_inputs(id, request):
    """
    `days` from the body or query; `apply` from the body only, and only a
    literal boolean — a calibration that changes a live policy should not be
    triggered by a string that happens to be truthy.
    """
    source = request.data if request.method == "POST" else request.query_params
    days = source.get("days", undefined)
    apply = request.data.get("apply", undefined) if request.method == "POST" else undefined

    errors = list()
    application = parse_application_id(id, errors)

    if days is not undefined and not is_window(days):
        errors.append(msg_void_or_decimal.new(path="days", context=dict(maximum=MAX_DAYS)))

    if apply is not undefined and not isinstance(apply, bool):
        errors.append(msg_bool.new(path="apply"))

    data = None if errors else (
        Struct(
            application=application,
            days=Calibrator.WINDOW_DAYS if days is undefined else int(days),
            apply=False if apply is undefined else apply,
        )
    )

    return (data, errors)


def is_window(value):
    try:
        return 1 <= int(value) <= MAX_DAYS
    except (TypeError, ValueError):
        return False
