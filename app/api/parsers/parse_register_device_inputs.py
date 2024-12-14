from audit import events
from devkit import undefined
from devkit.struct import Struct
from devkit.message import Message
from core.models import Application
from devkit.checks import is_uuid_str, is_dense_str


def parse_register_device_inputs(id, request):
    client_id = request.data.get("client_id", undefined)
    device_query_id = request.data.get("device_query_id", undefined)

    errors = list()
    application = None

    if not is_uuid_str(id):
        errors.append(
            # TODO: Refine the below message for reuse
            Message(
                code="uuid",
                path="id",
                text="Some texts that will be refined goes here",
            )
        )
    else:
        application = Application.objects.filter(id=id).first()

        if not application:
            errors.append(
                # TODO: Refine the below message for reuse
                Message(
                    code="app_ref_exist",
                    path="id",
                    text="Some texts that will be refined goes here",
                )
            )
    
    if client_id is undefined:
        errors.append(
            # TODO: Refine the below message for reuse
            Message(
                code="required",
                path="client_id",
                text="Some texts that will be refined goes here",
            )
        )
    elif not is_dense_str(client_id):
        errors.append(
            # TODO: Refine the below message for reuse
            Message(
                code="dense",
                path="client_id",
                text="Some texts that will be refined goes here",
            )
        )

    if device_query_id is undefined:
        errors.append(
            # TODO: Refine the below message for reuse
            Message(
                code="required",
                path="device_query_id",
                text="Some texts that will be refined goes here",
            )
        )
    elif not is_dense_str(device_query_id):
        errors.append(
            # TODO: Refine the below message for reuse
            Message(
                code="dense",
                path="device_query_id",
                text="Some texts that will be refined goes here",
            )
        )

    data = None if errors else (
        Struct(
            client_id=client_id,
            application=application,
            device_query_id=device_query_id,
        )
    )

    return (data, errors)
