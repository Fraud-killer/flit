from core.audit import events
from devkit import undefined
from devkit.struct import Struct
from core.models import Application
from devkit.checks import is_uuid_str
from devkit.messages import msg_in_choices, msg_uuid
from core.messages.applications import msg_app_ref_exist


modes_dict = {
    "client": events.ClientEvent, 
    "transaction": events.TransactionEvent,
}


def parse_audit_inputs(id, mode, request):
    event = None
    errors = list()
    application = None
    is_valid_mode = mode in modes_dict

    if not is_valid_mode:
        errors.append(
            msg_in_choices.new(
                path="mode",
                context=dict(choices=list(modes_dict)),
            )
        )

    if not is_uuid_str(id):
        errors.append(
            msg_uuid.new(path="id")
        )
    else:
        application = Application.objects.filter(id=id).first()

        if not application:
            errors.append(msg_app_ref_exist.new(path="id"))

    if is_valid_mode and application:
        event = modes_dict[mode](**request.data)
        errors.extend(event.verify(application.policy))

    data = None if errors else (
        Struct(
            event=event,
            application=application,
            policy=application.policy,
        )
    )

    return (data, errors)
