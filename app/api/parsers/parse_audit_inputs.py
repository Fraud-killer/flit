from audit import events
from devkit import undefined
from devkit.struct import Struct
from devkit.message import Message
from core.models import Application
from devkit.checks import is_uuid_str


def parse_audit_inputs(id, mode, request):
    modes_dict = {
        "client": events.ClientEvent, 
        "transaction": events.TransactionEvent,
    }

    event = None
    errors = list()
    application = None

    if mode not in modes_dict:
        errors.append(
            # TODO: Refine the below message for reuse
            Message(
                code="in_choices",
                path="mode",
                context=dict(choices=list(modes_dict)),
                text="Some texts that will be refined goes here",
            )
        )
    else:
        event = modes_dict[mode](**request.data)
        errors.extend(event.verify())

    if id is undefined:
        errors.append(
            # TODO: Refine the below message for reuse
            Message(
                code="required",
                path="id",
                text="Some texts that will be refined goes here",
            )
        )
    elif not is_uuid_str(id):
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

    data = None if errors else (
        Struct(
            event=event,
            application=application,
            policy=application.policy,
        )
    )

    return (data, errors)
