from devkit import undefined
from devkit.struct import Struct
from core.models import Case, CaseStatus
from devkit.checks import is_uuid_str, is_trimmed_str
from devkit.messages import msg_uuid, msg_required, msg_in_choices, msg_trimmed_string
from core.messages.cases import msg_case_ref_exist

from .parse_application_id import parse_application_id


def parse_case_inputs(id, case_id, request):
    status = request.data.get("status", undefined)
    note = request.data.get("note", undefined)

    errors = list()
    case = None
    application = parse_application_id(id, errors)

    if status is undefined:
        errors.append(msg_required.new(path="status"))
    elif status not in CaseStatus.VALUES:
        errors.append(msg_in_choices.new(path="status", context=dict(choices=CaseStatus.VALUES)))

    if note is not undefined and not is_trimmed_str(note or ""):
        errors.append(msg_trimmed_string.new(path="note"))

    if not is_uuid_str(case_id):
        errors.append(msg_uuid.new(path="case_id"))
    elif application:
        case = Case.objects.filter(id=case_id, application=application).first()
        if not case:
            errors.append(msg_case_ref_exist.new(path="case_id"))

    data = None if errors else (
        Struct(
            case=case,
            status=status,
            application=application,
            note="" if note is undefined else note,
        )
    )

    return (data, errors)
