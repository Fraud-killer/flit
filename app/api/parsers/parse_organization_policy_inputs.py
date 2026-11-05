from devkit import undefined
from devkit.struct import Struct
from devkit.checks import is_uuid_str
from devkit.messages import msg_dict, msg_uuid, msg_in_choices
from core.models import Organization, Enforcement
from core.messages.applications import msg_app_ref_exist
from core.decision import validate_rules

from .parse_simulation_inputs import is_ratio


def parse_organization_policy_inputs(id, request):
    errors = list()
    organization = None
    changes = dict()

    if not is_uuid_str(id):
        errors.append(msg_uuid.new(path="id"))
    else:
        organization = Organization.objects.filter(id=id).first()
        if not organization:
            errors.append(msg_app_ref_exist.new(path="id", context=dict(resource="organization")))

    if request.method == "PATCH":
        body = request.data if isinstance(request.data, dict) else {}

        rules = body.get("rules", undefined)
        if rules is not undefined:
            problems = validate_rules(rules)
            if problems:
                errors.extend(problems)
            else:
                changes["rules"] = rules

        for key in ("max_block_at", "max_review_at"):
            value = body.get(key, undefined)
            if value is undefined:
                continue
            if value is not None and not is_ratio(value):
                errors.append(msg_dict.new(path=key, context=dict(values="a number between 0 and 1, or null")))
            else:
                changes[key] = None if value is None else float(value)

        enforcement = body.get("required_enforcement", undefined)
        if enforcement is not undefined:
            if enforcement is not None and enforcement != Enforcement.ENFORCING:
                errors.append(msg_in_choices.new(
                    path="required_enforcement", context=dict(choices=[Enforcement.ENFORCING, None]),
                ))
            else:
                changes["required_enforcement"] = enforcement

        disabled = body.get("disabled_rules", undefined)
        if disabled is not undefined:
            if not (isinstance(disabled, list) and all(isinstance(n, str) and n for n in disabled)):
                errors.append(msg_dict.new(path="disabled_rules", context=dict(values="rule class names")))
            else:
                changes["disabled_rules"] = sorted(set(disabled))

    data = None if errors else Struct(organization=organization, changes=changes)

    return (data, errors)
