from devkit import undefined
from devkit.struct import Struct
from core.models import AuditLog
from core.models.challenge import ChallengeMethod
from devkit.checks import is_uuid_str, is_dense_str
from devkit.messages import msg_uuid, msg_required, msg_in_choices, msg_dense_string
from core.messages.audits import msg_audit_ref_exist

from .parse_application_id import parse_application_id


def parse_challenge_inputs(id, request):
    client_id = request.data.get("client_id", undefined)
    method = request.data.get("method", ChallengeMethod.TURNSTILE)
    audit_id = request.data.get("audit_id", undefined)

    errors = list()
    audit_log = None
    identity_key_ids = []
    application = parse_application_id(id, errors)

    if client_id is undefined:
        errors.append(msg_required.new(path="client_id"))
    elif not is_dense_str(client_id):
        errors.append(msg_dense_string.new(path="client_id"))

    if method not in ChallengeMethod.VALUES:
        context = dict(choices=ChallengeMethod.VALUES)
        errors.append(msg_in_choices.new(path="method", context=context))

    if audit_id is not undefined:
        if not is_uuid_str(audit_id):
            errors.append(msg_uuid.new(path="audit_id"))
        elif application:
            audit_log = AuditLog.objects.filter(
                application_id=application.id, id=audit_id,
            ).first()

            if not audit_log:
                errors.append(msg_audit_ref_exist.new(path="audit_id"))
            else:
                # Carry the decision's identity keys onto the challenge, so
                # its outcome can be attributed to the same actor the
                # decision was about.
                identity_key_ids = (audit_log.context or {}).get("identity_key_ids") or []

    data = None if errors else (
        Struct(
            client_id=client_id,
            method=method,
            audit_log=audit_log,
            identity_key_ids=identity_key_ids,
            application=application,
        )
    )

    return (data, errors)
