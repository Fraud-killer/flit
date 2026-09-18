from devkit import undefined
from devkit.struct import Struct
from core.models import Application
from devkit.checks import is_dense_str
from devkit.messages import msg_required, msg_dense_string, msg_dict
from core.messages.applications import msg_collect_key_exist


MAX_SIGNAL_BYTES = 16 * 1024


def parse_collect_inputs(request):
    key = request.data.get("key", undefined)
    signals = request.data.get("signals", undefined)
    device_key = request.data.get("device_key", None)

    errors = list()
    application = None

    if key is undefined:
        errors.append(msg_required.new(path="key"))
    elif not is_dense_str(key):
        errors.append(msg_dense_string.new(path="key"))
    else:
        application = Application.objects.filter(collect_key=key).first()
        if not application:
            errors.append(msg_collect_key_exist.new(path="key"))

    if signals is undefined:
        errors.append(msg_required.new(path="signals"))
    elif not isinstance(signals, dict):
        errors.append(msg_dict.new(path="signals"))
    elif len(str(signals)) > MAX_SIGNAL_BYTES:
        errors.append(msg_dict.new(path="signals", context=dict(max_bytes=MAX_SIGNAL_BYTES)))

    if device_key is not None and not is_dense_str(device_key):
        device_key = None

    data = None if errors else (
        Struct(
            signals=signals,
            device_key=device_key,
            application=application,
        )
    )

    return (data, errors)
