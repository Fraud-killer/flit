from devkit import undefined
from devkit.struct import Struct
from core.models import Application
from devkit.checks import is_uuid_str, is_dense_str
from core.messages.applications import msg_app_ref_exist
from devkit.messages import msg_uuid, msg_required, msg_dense_string


def parse_register_device_inputs(id, request):
    client_id = request.data.get("client_id", undefined)
    device_query_id = request.data.get("device_query_id", undefined)

    errors = list()
    application = None

    if not is_uuid_str(id):
        errors.append(
            msg_uuid.new(path="id")
        )
    else:
        application = Application.objects.filter(id=id).first()

        if not application:
            errors.append(msg_app_ref_exist.new(path="id"))

    if client_id is undefined:
        errors.append(
            msg_required.new(path="client_id")
        )
    elif not is_dense_str(client_id):
        errors.append(
            msg_dense_string.new(path="client_id")
        )

    if device_query_id is undefined:
        errors.append(
            msg_required.new(path="device_query_id")
        )
    elif not is_dense_str(device_query_id):
        errors.append(
            msg_dense_string.new(path="device_query_id")
        )

    data = None if errors else (
        Struct(
            client_id=client_id,
            application=application,
            device_query_id=device_query_id,
        )
    )

    return (data, errors)
