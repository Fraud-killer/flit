"""
Inputs for Agent FLIT's endpoints: policy changes, investigations, approvals,
memories, monitors, playbooks. Each parser returns (Struct, errors).
"""

from devkit import undefined
from devkit.struct import Struct
from devkit.checks import is_uuid_str, is_trimmed_str
from devkit.messages import msg_dict, msg_uuid, msg_required, msg_in_choices, msg_trimmed_string, msg_void_or_decimal

from core.models import (
    AgentMode, Investigation, InvestigationStep, StepStatus, AgentMemory, MemoryKind, Monitor,
    MonitorMetric, MonitorAction, Organization,
)
from core.messages.agent import msg_rules_invalid
from core.messages.policies import msg_outbound_url
from core.messages.applications import msg_app_ref_exist
from core.outbound import BlockedAddressError, check_url

from .parse_application_id import parse_application_id


def _body(request):
    return request.data if isinstance(request.data, dict) else {}


def _number(value, path, errors, minimum, maximum, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(msg_void_or_decimal.new(path=path))
        return None
    if integer and int(value) != value:
        errors.append(msg_void_or_decimal.new(path=path))
        return None
    if not (minimum <= value <= maximum):
        errors.append(msg_void_or_decimal.new(path=path, context=dict(minimum=minimum, maximum=maximum)))
        return None
    return int(value) if integer else float(value)


def parse_organization_id(id, errors):
    if not is_uuid_str(id):
        errors.append(msg_uuid.new(path="id"))
        return None
    organization = Organization.objects.filter(id=id).first()
    if not organization:
        errors.append(msg_app_ref_exist.new(path="id", context=dict(resource="organization")))
    return organization


def parse_agent_policy_changes(body, errors):
    from core.agent import validate_rule_list, Tools

    changes = {}
    known = set(Tools.names())

    enabled = body.get("enabled", undefined)
    if enabled is not undefined:
        if not isinstance(enabled, bool):
            errors.append(msg_in_choices.new(path="enabled", context=dict(choices=[True, False])))
        else:
            changes["enabled"] = enabled

    mode = body.get("mode", undefined)
    if mode is not undefined:
        if mode not in AgentMode.VALUES:
            errors.append(msg_in_choices.new(path="mode", context=dict(choices=AgentMode.VALUES)))
        else:
            changes["mode"] = mode

    for name in ("allow", "ask", "deny"):
        rules = body.get(name, undefined)
        if rules is not undefined:
            problems = validate_rule_list(rules, known)
            if problems:
                errors.append(msg_rules_invalid.new(path=name, context=dict(problems=problems[:6])))
            else:
                changes[name] = sorted(set(r.strip() for r in rules))

    auto_rules = body.get("auto_rules", undefined)
    if auto_rules is not undefined:
        if not isinstance(auto_rules, str) or len(auto_rules) > 4000:
            errors.append(msg_trimmed_string.new(path="auto_rules"))
        else:
            changes["auto_rules"] = auto_rules.strip()

    hook_url = body.get("hook_url", undefined)
    if hook_url is not undefined:
        if hook_url in (None, ""):
            changes["hook_url"] = None
        else:
            try:
                check_url(str(hook_url))
                changes["hook_url"] = str(hook_url)
            except (BlockedAddressError, ValueError):
                errors.append(msg_outbound_url.new(path="hook_url"))

    for name, minimum, maximum, integer in (
        ("hook_timeout_ms", 100, 10000, True), ("max_cost_usd", 0.05, 100.0, False),
        ("daily_budget_usd", 0.5, 10000.0, False), ("max_turns", 2, 100, True),
    ):
        value = body.get(name, undefined)
        if value is not undefined:
            parsed = _number(value, name, errors, minimum, maximum, integer=integer)
            if parsed is not None:
                changes[name] = parsed

    model = body.get("model", undefined)
    if model is not undefined:
        if model in (None, ""):
            changes["model"] = None
        elif not isinstance(model, str) or not model.startswith("claude-") or len(model) > 80:
            errors.append(msg_trimmed_string.new(path="model"))
        else:
            changes["model"] = model

    investigate = body.get("investigate_cases", undefined)
    if investigate is not undefined:
        if not isinstance(investigate, bool):
            errors.append(msg_in_choices.new(path="investigate_cases", context=dict(choices=[True, False])))
        else:
            changes["investigate_cases"] = investigate

    return changes


def parse_agent_policy_inputs(id, request, *, scope="application"):
    errors = []
    owner = parse_application_id(id, errors) if scope == "application" else parse_organization_id(id, errors)
    changes = parse_agent_policy_changes(_body(request), errors) if request.method == "PATCH" else {}
    data = None if errors else Struct(owner=owner, changes=changes)
    return data, errors


def parse_investigation_inputs(id, request):
    errors = []
    application = parse_application_id(id, errors)
    body = _body(request)

    playbook = body.get("playbook", "investigate_case")
    if not isinstance(playbook, str) or not is_trimmed_str(playbook) or len(playbook) > 80:
        errors.append(msg_trimmed_string.new(path="playbook"))

    subject = {}
    for key in ("client_id", "device_id", "ip_address"):
        value = body.get(key, undefined)
        if value is not undefined:
            if not isinstance(value, str) or not is_trimmed_str(value) or len(value) > 120:
                errors.append(msg_trimmed_string.new(path=key))
            else:
                subject[key] = value
    hours = body.get("hours", undefined)
    if hours is not undefined:
        parsed = _number(hours, "hours", errors, 1, 168, integer=True)
        if parsed is not None:
            subject["hours"] = parsed

    case = None
    case_id = body.get("case_id", undefined)
    if case_id is not undefined:
        if not is_uuid_str(case_id):
            errors.append(msg_uuid.new(path="case_id"))
        elif application:
            from core.models import Case
            case = Case.objects.filter(id=case_id, application=application).select_related("audit_log").first()
            if case is None:
                errors.append(msg_app_ref_exist.new(path="case_id", context=dict(resource="case")))

    mode = body.get("mode", undefined)
    if mode is not undefined and mode not in AgentMode.VALUES:
        errors.append(msg_in_choices.new(path="mode", context=dict(choices=AgentMode.VALUES)))

    data = None if errors else Struct(
        application=application, playbook=playbook, subject=subject, case=case,
        mode=None if mode is undefined else mode,
    )
    return data, errors


def parse_investigation_ref(id, investigation_id, errors):
    application = parse_application_id(id, errors)
    investigation = None
    if not is_uuid_str(investigation_id):
        errors.append(msg_uuid.new(path="investigation_id"))
    elif application:
        investigation = Investigation.objects.filter(id=investigation_id, application=application).first()
        if investigation is None:
            errors.append(msg_app_ref_exist.new(path="investigation_id", context=dict(resource="investigation")))
    return application, investigation


def parse_step_decision_inputs(id, investigation_id, step_id, request):
    errors = []
    application, investigation = parse_investigation_ref(id, investigation_id, errors)
    body = _body(request)

    step = None
    if not is_uuid_str(step_id):
        errors.append(msg_uuid.new(path="step_id"))
    elif investigation:
        step = InvestigationStep.objects.filter(id=step_id, investigation=investigation).first()
        if step is None:
            errors.append(msg_app_ref_exist.new(path="step_id", context=dict(resource="step")))

    decision = body.get("decision", undefined)
    if decision is undefined:
        errors.append(msg_required.new(path="decision"))
    elif decision not in ("approve", "reject"):
        errors.append(msg_in_choices.new(path="decision", context=dict(choices=["approve", "reject"])))

    note = body.get("note", "")
    if not isinstance(note, str) or len(note) > 1000:
        errors.append(msg_trimmed_string.new(path="note"))

    data = None if errors else Struct(
        application=application, investigation=investigation, step=step,
        approved=decision == "approve", note=note.strip(),
    )
    return data, errors


def parse_memory_inputs(id, request):
    errors = []
    application = parse_application_id(id, errors)
    body = _body(request)

    kind = body.get("kind", undefined)
    if kind is undefined:
        errors.append(msg_required.new(path="kind"))
    elif kind not in MemoryKind.VALUES:
        errors.append(msg_in_choices.new(path="kind", context=dict(choices=MemoryKind.VALUES)))

    fields = {}
    for key, maximum in (("name", 80), ("description", 200), ("body", 4000)):
        value = body.get(key, undefined)
        if value is undefined:
            errors.append(msg_required.new(path=key))
        elif not isinstance(value, str) or not is_trimmed_str(value) or len(value) > maximum:
            errors.append(msg_trimmed_string.new(path=key))
        else:
            fields[key] = value

    tags = body.get("tags", [])
    if not (isinstance(tags, list) and all(isinstance(t, str) and 0 < len(t) <= 40 for t in tags) and len(tags) <= 10):
        errors.append(msg_dict.new(path="tags", context=dict(values="up to 10 short strings")))

    refers_to = body.get("refers_to", {})
    if not isinstance(refers_to, dict) or len(refers_to) > 10:
        errors.append(msg_dict.new(path="refers_to"))

    application_only = body.get("application_only", True)
    if not isinstance(application_only, bool):
        errors.append(msg_in_choices.new(path="application_only", context=dict(choices=[True, False])))

    data = None if errors else Struct(
        application=application, kind=kind, tags=tags, refers_to=refers_to, application_only=application_only, **fields,
    )
    return data, errors


def parse_memory_ref(id, memory_id, errors):
    application = parse_application_id(id, errors)
    memory = None
    if not is_uuid_str(memory_id):
        errors.append(msg_uuid.new(path="memory_id"))
    elif application:
        memory = AgentMemory.objects.filter(id=memory_id, organization=application.organization).first()
        if memory is None:
            errors.append(msg_app_ref_exist.new(path="memory_id", context=dict(resource="memory")))
    return application, memory


def parse_monitor_inputs(id, request):
    errors = []
    application = parse_application_id(id, errors)
    body = _body(request)

    name = body.get("name", undefined)
    if name is undefined:
        errors.append(msg_required.new(path="name"))
    elif not isinstance(name, str) or not is_trimmed_str(name) or len(name) > 120:
        errors.append(msg_trimmed_string.new(path="name"))

    metric = body.get("metric", undefined)
    if metric is undefined:
        errors.append(msg_required.new(path="metric"))
    elif metric not in MonitorMetric.VALUES:
        errors.append(msg_in_choices.new(path="metric", context=dict(choices=MonitorMetric.VALUES)))

    factor = body.get("factor", "")
    if not isinstance(factor, str) or len(factor) > 80:
        errors.append(msg_trimmed_string.new(path="factor"))
    if metric == MonitorMetric.FACTOR and not factor:
        errors.append(msg_required.new(path="factor"))

    threshold = _number(body.get("threshold", undefined), "threshold", errors, 1, 100000, integer=True) if "threshold" in body else errors.append(msg_required.new(path="threshold"))
    window = _number(body.get("window_minutes", 60), "window_minutes", errors, 5, 10080, integer=True)
    expires_hours = _number(body.get("expires_hours", 24), "expires_hours", errors, 1, 24 * 30, integer=True)

    action = body.get("action", MonitorAction.ALERT)
    if action not in MonitorAction.VALUES:
        errors.append(msg_in_choices.new(path="action", context=dict(choices=MonitorAction.VALUES)))

    playbook = body.get("playbook", "")
    if not isinstance(playbook, str) or len(playbook) > 80:
        errors.append(msg_trimmed_string.new(path="playbook"))
    if action == MonitorAction.INVESTIGATE and not playbook:
        errors.append(msg_required.new(path="playbook"))

    subject = {}
    for key in ("client_id", "device_id", "ip_address"):
        value = body.get(key, undefined)
        if value is not undefined:
            if not isinstance(value, str) or not is_trimmed_str(value) or len(value) > 120:
                errors.append(msg_trimmed_string.new(path=key))
            else:
                subject[key] = value

    data = None if errors else Struct(
        application=application, name=name, metric=metric, factor=factor, threshold=threshold,
        window_minutes=window, expires_hours=expires_hours, action=action, playbook=playbook, subject=subject,
    )
    return data, errors


def parse_monitor_ref(id, monitor_id, errors):
    application = parse_application_id(id, errors)
    monitor = None
    if not is_uuid_str(monitor_id):
        errors.append(msg_uuid.new(path="monitor_id"))
    elif application:
        monitor = Monitor.objects.filter(id=monitor_id, application=application).first()
        if monitor is None:
            errors.append(msg_app_ref_exist.new(path="monitor_id", context=dict(resource="monitor")))
    return application, monitor


def parse_playbook_inputs(id, request):
    errors = []
    organization = parse_organization_id(id, errors)
    body = _body(request)
    text = body.get("text", undefined)
    if request.method == "PUT":
        if text is undefined:
            errors.append(msg_required.new(path="text"))
        elif not isinstance(text, str) or not text.strip() or len(text) > 40000:
            errors.append(msg_trimmed_string.new(path="text"))
    data = None if errors else Struct(organization=organization, text=None if text is undefined else text)
    return data, errors
