"""
Write tools: what the agent may change. Every one goes through the permission
ladder, the bank's hook and, where marked, an independent verifier before it
runs. Each describes itself in a sentence, because a person may be the one
deciding.

The agent never enforces directly. `block_actor` writes a rule into the policy
the engine reads; `case_resolve` closes a case the way a reviewer would. Both
reuse the services the console uses, so the loosening guard and the audit
chain apply exactly as they do for a person.
"""

from datetime import timedelta

from django.utils import timezone

from .base import Tool, ToolKind, ToolError, sanitize, iso


def _str(min_length=1, max_length=120, **extra):
    return dict(type="string", minLength=min_length, maxLength=max_length, **extra)


class CaseResolveTool(Tool):
    name = "case_resolve"
    kind = ToolKind.WRITE
    needs_verification = True
    description = (
        "Close a case as confirmed_fraud or cleared, with a short note. Closing labels the "
        "decision behind it and publishes the outcome to the protection network, so this is "
        "the write with the longest reach. Never clear a case where a control fired."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "case_id": _str(max_length=40),
            "status": {"type": "string", "enum": ["confirmed_fraud", "cleared"]},
            "note": _str(min_length=1, max_length=600),
        },
        "required": ["case_id", "status", "note"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return inputs.get("status", "")

    @classmethod
    def describe(cls, inputs):
        return f"Close case {inputs.get('case_id')} as {inputs.get('status')}: {inputs.get('note', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.models import CaseNote
        from .read_tools import _case

        case = _case(inputs["case_id"], context)
        if not case.is_open:
            raise ToolError(f"Case is already {case.status}")
        if inputs["status"] == "cleared" and any(
            code in ("sanctioned_address", "policy_block")
            for d in ([case.audit_log] + (list(case.decisions()) if case.campaign_key else []))
            for code in (d.risk_factors or [])
        ):
            raise ToolError("A control fired on this case; it is not cleared by the agent")

        note = f"[agent] {inputs['note']}"
        case.resolve(status=inputs["status"], note=note, assignee=None)
        CaseNote.objects.create(case=case, body=note, author=None)
        return dict(case_id=str(case.id), status=case.status, closed_at=iso(case.closed_at))


class CaseNoteTool(Tool):
    name = "case_note"
    kind = ToolKind.WRITE
    description = "Add a note to a case for the reviewers: what was checked and what it showed."
    input_schema = {
        "type": "object",
        "properties": {"case_id": _str(max_length=40), "body": _str(max_length=1500)},
        "required": ["case_id", "body"],
        "additionalProperties": False,
    }

    @classmethod
    def describe(cls, inputs):
        return f"Add a note to case {inputs.get('case_id')}"

    @classmethod
    def run(cls, inputs, context):
        from core.models import CaseNote
        from .read_tools import _case

        case = _case(inputs["case_id"], context)
        note = CaseNote.objects.create(case=case, body=f"[agent] {inputs['body']}", author=None)
        return dict(case_id=str(case.id), note_id=str(note.id))


BLOCK_SUBJECTS = ("ip", "cidr", "device", "client_id", "email_root", "email_domain", "wallet", "asn", "country")


class BlockActorTool(Tool):
    name = "block_actor"
    kind = ToolKind.WRITE
    needs_verification = True
    description = (
        "Add a time-limited block rule to this application's decision policy for one actor: "
        "an ip, cidr, device, client_id, email_root, email_domain, wallet, asn or country. "
        "From then on the engine blocks matching events. This tightens policy and is never "
        "a loosening. Prefer the narrowest subject that covers the evidence; a country or "
        "ASN block affects everyone behind it."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "subject": {"type": "string", "enum": list(BLOCK_SUBJECTS)},
            "pattern": _str(max_length=200),
            "reason": _str(max_length=300),
            "expires_hours": {"type": "integer", "minimum": 1, "maximum": 24 * 90},
        },
        "required": ["subject", "pattern", "reason", "expires_hours"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return f"{inputs.get('subject', '')}:{inputs.get('pattern', '')}"

    @classmethod
    def describe(cls, inputs):
        return (
            f"Block {inputs.get('subject')} {inputs.get('pattern')} for {inputs.get('expires_hours')} hours: "
            f"{inputs.get('reason', '')}"
        )

    @classmethod
    def run(cls, inputs, context):
        from core.decision import validate_rules, normalize_rules
        from core.services.policy_change import PolicyChange, PolicyLooseningForbidden

        policy = context.application.policy
        rules = normalize_rules(policy.rules)
        expires_at = context.now + timedelta(hours=inputs["expires_hours"])
        entry = dict(
            subject=inputs["subject"], pattern=inputs["pattern"],
            reason=f"[agent] {inputs['reason']}", expires_at=expires_at.isoformat(),
        )
        for existing in rules["block"]:
            if existing.get("subject") == entry["subject"] and existing.get("pattern") == entry["pattern"]:
                raise ToolError("An identical block rule already exists")
        rules["block"].append(entry)

        problems = validate_rules(rules)
        if problems:
            raise ToolError("; ".join(p.get("text", str(p)) for p in problems))

        try:
            PolicyChange.apply(policy=policy, changes=dict(rules=rules), actor=context.actor)
        except PolicyLooseningForbidden as refusal:
            raise ToolError(f"Refused as a loosening: {refusal.loosened}")

        return dict(rule=entry, block_rules=len(rules["block"]))


class PolicyChangeTool(Tool):
    name = "policy_change"
    kind = ToolKind.WRITE
    needs_verification = True
    description = (
        "Change this application's decision policy: thresholds, weights, disabled_rules or "
        "shadow_rules. The agent may only tighten; any loosening (raising a threshold, "
        "lowering a weight, disabling or shadowing a rule) is refused. Always simulate first "
        "and cite the simulation in the reason."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "thresholds": {
                "type": "object",
                "properties": {
                    "block_at": {"type": "number", "minimum": 0, "maximum": 1},
                    "review_at": {"type": "number", "minimum": 0, "maximum": 1},
                    "challenge_at": {"type": "number", "minimum": 0, "maximum": 1},
                },
                "additionalProperties": False,
            },
            "weights": {"type": "object"},
            "shadow_rules": {"type": "array", "items": _str(max_length=80), "maxItems": 50},
            "reason": _str(max_length=400),
        },
        "required": ["reason"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return ",".join(sorted(k for k in inputs if k != "reason"))

    @classmethod
    def describe(cls, inputs):
        changes = {k: v for k, v in inputs.items() if k != "reason"}
        return f"Change policy {changes}: {inputs.get('reason', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.services.policy_change import PolicyChange, PolicyLooseningForbidden

        changes = {k: v for k, v in inputs.items() if k != "reason"}
        if not changes:
            raise ToolError("Nothing to change")
        weights = changes.get("weights")
        if weights is not None:
            if not weights or not all(isinstance(v, (int, float)) and 0 <= v <= 1 for v in weights.values()):
                raise ToolError("weights must be a non-empty map of numbers between 0 and 1")
            if all(float(v) == 0 for v in weights.values()):
                raise ToolError("All-zero weights are refused")
        try:
            loosened = PolicyChange.apply(policy=context.application.policy, changes=changes, actor=context.actor)
        except PolicyLooseningForbidden as refusal:
            raise ToolError(f"Refused as a loosening: {refusal.loosened}")
        return dict(applied=changes, loosened=loosened)


class OpenMonitorTool(Tool):
    name = "open_monitor"
    kind = ToolKind.WRITE
    description = (
        "Watch a subject and alert when a condition is met: block_streak, decisions, blocks, "
        "a factor seen N times, or open_cases, within a window. Optionally queue an "
        "investigation under a playbook when it fires. Monitors expire."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "name": _str(max_length=120),
            "client_id": _str(),
            "device_id": _str(max_length=100),
            "ip_address": _str(max_length=64),
            "metric": {"type": "string", "enum": ["block_streak", "decisions", "blocks", "factor", "open_cases"]},
            "factor": _str(max_length=80),
            "threshold": {"type": "integer", "minimum": 1, "maximum": 100000},
            "window_minutes": {"type": "integer", "minimum": 5, "maximum": 10080},
            "action": {"type": "string", "enum": ["alert", "investigate"]},
            "playbook": _str(max_length=80),
            "expires_hours": {"type": "integer", "minimum": 1, "maximum": 24 * 30},
        },
        "required": ["name", "metric", "threshold", "expires_hours"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return inputs.get("metric", "")

    @classmethod
    def describe(cls, inputs):
        return f"Watch {inputs.get('name')}: {inputs.get('metric')} >= {inputs.get('threshold')} for {inputs.get('expires_hours')}h"

    @classmethod
    def run(cls, inputs, context):
        from core.models import Monitor

        subject = {k: inputs[k] for k in ("client_id", "device_id", "ip_address") if inputs.get(k)}
        if inputs["metric"] == "factor" and not inputs.get("factor"):
            raise ToolError("A factor monitor needs a factor code")
        if inputs.get("action") == "investigate" and not inputs.get("playbook"):
            raise ToolError("An investigating monitor needs a playbook")

        monitor = Monitor.objects.create(
            application=context.application, name=inputs["name"], subject=subject,
            metric=inputs["metric"], factor=inputs.get("factor", ""), threshold=inputs["threshold"],
            window_minutes=inputs.get("window_minutes", 60), action=inputs.get("action", "alert"),
            playbook=inputs.get("playbook", ""), expires_at=context.now + timedelta(hours=inputs["expires_hours"]),
            source_investigation=context.investigation,
            created_by=context.actor.entity if getattr(context.actor, "is_user", False) else None,
        )
        return dict(monitor_id=str(monitor.id), expires_at=iso(monitor.expires_at))


class RememberTool(Tool):
    name = "remember"
    kind = ToolKind.WRITE
    description = (
        "Save one fact for future investigations in this organization: a fact about the "
        "estate, a campaign's shape, or a reference. One fact per memory, with a one-line "
        "description used to find it later. What the agent saves is unconfirmed until a "
        "person confirms it. Do not save what FLIT already records (decisions, cases, "
        "labels); save what was surprising."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "kind": {"type": "string", "enum": ["fact", "campaign", "reference"]},
            "name": _str(min_length=3, max_length=80),
            "description": _str(min_length=10, max_length=200),
            "body": _str(min_length=10, max_length=2000),
            "tags": {"type": "array", "items": _str(max_length=40), "maxItems": 10},
            "refers_to": {"type": "object"},
        },
        "required": ["kind", "name", "description", "body"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return inputs.get("kind", "")

    @classmethod
    def describe(cls, inputs):
        return f"Remember [{inputs.get('kind')}] {inputs.get('name')}: {inputs.get('description', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.agent.memory import Memory, MemoryProtected

        try:
            memory = cls.save(inputs, context, Memory)
        except MemoryProtected as protected:
            raise ToolError(
                f"A person confirmed the memory {protected.memory.name!r}; the agent does not rewrite it. "
                "Save what you learned under a different name."
            )
        return dict(memory_id=str(memory.id), name=memory.name, confirmed=memory.is_confirmed)

    @classmethod
    def save(cls, inputs, context, Memory):
        return Memory.save(
            organization=context.organization, application=context.application,
            kind=inputs["kind"], name=inputs["name"], description=inputs["description"],
            body=inputs["body"], tags=inputs.get("tags") or [], refers_to=inputs.get("refers_to") or {},
            provenance=dict(
                kind="agent",
                investigation_id=str(context.investigation.id) if context.investigation else None,
            ),
        )


WRITE_TOOLS = (CaseResolveTool, CaseNoteTool, BlockActorTool, PolicyChangeTool, OpenMonitorTool, RememberTool)
