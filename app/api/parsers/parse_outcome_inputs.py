from devkit import undefined
from devkit.struct import Struct
from core.models import AuditLog
from core.audit.models import AuditLogLabel
from devkit.checks import is_uuid_str, is_dense_str
from devkit.messages import msg_uuid, msg_required, msg_in_choices, msg_dense_string
from core.messages.audits import msg_audit_ref_exist, msg_audit_or_event_id

from .parse_application_id import parse_application_id


def parse_outcome_inputs(id, request):
    audit_id = request.data.get("audit_id", undefined)
    event_id = request.data.get("event_id", undefined)
    label = request.data.get("label", undefined)

    errors = list()
    audit_log = None
    application = parse_application_id(id, errors)

    if label is undefined:
        errors.append(msg_required.new(path="label"))
    elif label not in AuditLogLabel.VALUES:
        context = dict(choices=AuditLogLabel.VALUES)
        errors.append(msg_in_choices.new(path="label", context=context))

    if audit_id is undefined and event_id is undefined:
        errors.append(msg_audit_or_event_id.new(path="audit_id"))
    elif audit_id is not undefined and not is_uuid_str(audit_id):
        errors.append(msg_uuid.new(path="audit_id"))
    elif audit_id is undefined and not is_dense_str(event_id):
        errors.append(msg_dense_string.new(path="event_id"))
    elif application:
        audit_logs = AuditLog.objects.filter(application_id=application.id)

        if audit_id is not undefined:
            audit_log = audit_logs.filter(id=audit_id).first()
            path = "audit_id"
        else:
            # An event id can be audited more than once; label the latest.
            audit_log = audit_logs.filter(resource_id=event_id).order_by("-timestamp").first()
            path = "event_id"

        if not audit_log:
            errors.append(msg_audit_ref_exist.new(path=path))

    data = None if errors else (
        Struct(
            label=label,
            audit_log=audit_log,
            application=application,
        )
    )

    return (data, errors)
