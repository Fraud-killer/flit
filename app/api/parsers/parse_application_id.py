from core.models import Application
from devkit.checks import is_uuid_str
from devkit.messages import msg_uuid
from core.messages.applications import msg_app_ref_exist


def parse_application_id(id, errors):
    if not is_uuid_str(id):
        errors.append(msg_uuid.new(path="id"))
        return None

    application = Application.objects.filter(id=id).first()

    if not application:
        errors.append(msg_app_ref_exist.new(path="id"))

    return application
