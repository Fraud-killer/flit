from devkit.struct import Struct
from devkit.checks import is_uuid_str
from devkit.messages import msg_uuid
from core.models import DeviceIdentity
from core.messages.devices import msg_device_ref_exist

from .parse_application_id import parse_application_id


def parse_device_lookup_inputs(id, device_id):
    errors = list()
    device = None
    application = parse_application_id(id, errors)

    if not is_uuid_str(device_id):
        errors.append(msg_uuid.new(path="device_id"))
    elif application:
        # Identities are global; only expose ones this application has seen.
        device = (
            DeviceIdentity.objects
            .filter(id=device_id, account_links__application=application)
            .distinct()
            .first()
        )

        if not device:
            errors.append(msg_device_ref_exist.new(path="device_id"))

    data = None if errors else Struct(application=application, device=device)

    return (data, errors)
