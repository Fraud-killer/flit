from devkit.struct import Struct
from core.models import AuditLog, DeviceAccountLink
from devkit.checks import is_dense_str
from devkit.messages import msg_dense_string
from core.messages.accounts import msg_account_ref_exist

from .parse_application_id import parse_application_id


def parse_account_lookup_inputs(id, client_id):
    errors = list()
    application = parse_application_id(id, errors)

    if not is_dense_str(client_id or ""):
        errors.append(msg_dense_string.new(path="client_id"))
    elif application and not known_account(application, client_id):
        errors.append(msg_account_ref_exist.new(path="client_id"))

    data = None if errors else Struct(application=application, client_id=client_id)

    return (data, errors)


def known_account(application, client_id):
    """An account FLIT has decided on, or seen on a device, for this application."""
    return (
        AuditLog.objects.filter(application_id=application.id, actor_id=client_id).exists()
        or DeviceAccountLink.objects.filter(application=application, client_id=client_id).exists()
    )
