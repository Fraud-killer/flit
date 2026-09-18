from devkit.struct import Struct
from core.scoring import RiskLevel
from devkit.checks import is_dense_str
from core.audit.models import AuditLogLabel
from devkit.messages import msg_in_choices, msg_void_or_decimal

from .parse_application_id import parse_application_id


MAX_LIMIT = 200
DEFAULT_LIMIT = 50


def parse_decision_filters(id, request):
    errors = list()
    application = parse_application_id(id, errors)

    query = request.query_params
    level = query.get("level")
    label = query.get("label")

    if level is not None and level not in [value.value for value in RiskLevel]:
        context = dict(choices=[value.value for value in RiskLevel])
        errors.append(msg_in_choices.new(path="level", context=context))

    if label is not None and label not in AuditLogLabel.VALUES:
        errors.append(msg_in_choices.new(path="label", context=dict(choices=AuditLogLabel.VALUES)))

    limit, error = parse_integer(query.get("limit"), DEFAULT_LIMIT, 1, MAX_LIMIT)
    if error: errors.append(msg_void_or_decimal.new(path="limit"))

    offset, error = parse_integer(query.get("offset"), 0, 0, 100000)
    if error: errors.append(msg_void_or_decimal.new(path="offset"))

    days, error = parse_integer(query.get("days"), 30, 1, 365)
    if error: errors.append(msg_void_or_decimal.new(path="days"))

    data = None if errors else (
        Struct(
            days=days,
            level=level,
            label=label,
            limit=limit,
            offset=offset,
            application=application,
            factor=value_or_none(query.get("factor")),
            client_id=value_or_none(query.get("client_id")),
            device_id=value_or_none(query.get("device_id")),
            unlabelled=query.get("unlabelled") in ("1", "true", "yes"),
        )
    )

    return (data, errors)


def value_or_none(value):
    return value if is_dense_str(value or "") else None


def parse_integer(value, default, minimum, maximum):
    if value is None:
        return default, None

    try:
        number = int(value)
    except (TypeError, ValueError):
        return None, True

    if number < minimum or number > maximum:
        return None, True

    return number, None
