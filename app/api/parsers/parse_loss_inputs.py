from devkit.struct import Struct
from devkit.messages import msg_void_or_decimal

from .parse_application_id import parse_application_id
from .parse_decision_filters import parse_integer


def parse_loss_inputs(id, request):
    errors = list()
    application = parse_application_id(id, errors)

    days, error = parse_integer(request.query_params.get("days"), 30, 1, 365)
    if error: errors.append(msg_void_or_decimal.new(path="days"))

    data = None if errors else Struct(days=days, application=application)
    return (data, errors)
