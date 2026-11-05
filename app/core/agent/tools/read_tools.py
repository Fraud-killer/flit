"""
Read tools: what the agent may look at. Each wraps a service the console
already exposes, and returns the same facts the triage reader sees: shaped,
redacted, never a string a user typed.
"""

from datetime import timedelta

from django.db.models import Count
from django.utils import timezone
from devkit.struct import Struct

from .base import Tool, ToolKind, ToolError, sanitize, client_class, redact_email, iso


def _str(min_length=1, max_length=120, **extra):
    return dict(type="string", minLength=min_length, maxLength=max_length, **extra)


class DescribeAccountTool(Tool):
    name = "describe_account"
    kind = ToolKind.READ
    description = (
        "An account's profile as this application sees it: when first and last seen, "
        "thirty-day money flow (credits, debits, pass-through ratio, counterparties), the "
        "devices it has used and how many other accounts share them, mule signals, labels "
        "on record, open cases and total decisions."
    )
    input_schema = {
        "type": "object",
        "properties": {"client_id": _str()},
        "required": ["client_id"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return f"client_id:{inputs.get('client_id', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.services.describe_account import DescribeAccount
        account = DescribeAccount.call(application=context.application, client_id=inputs["client_id"])
        return sanitize(account)


class DescribeDeviceTool(Tool):
    name = "describe_device"
    kind = ToolKind.READ
    description = (
        "A device as this application sees it: source, flags, trust score, last country, "
        "the accounts that have used it, labels on record and its recent decisions."
    )
    input_schema = {
        "type": "object",
        "properties": {"device_id": _str(max_length=100)},
        "required": ["device_id"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return f"device:{inputs.get('device_id', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.models import DeviceIdentity
        from core.services.describe_device import DescribeDevice

        device = (
            DeviceIdentity.objects
            .filter(account_links__application=context.application)
            .filter(id=inputs["device_id"]).first()
            if _looks_like_uuid(inputs["device_id"]) else None
        ) or DeviceIdentity.objects.filter(
            external_id=inputs["device_id"], account_links__application=context.application,
        ).first()
        if device is None:
            raise ToolError("No such device for this application")
        return sanitize(DescribeDevice.call(device=device, application=context.application))


class ListDecisionsTool(Tool):
    name = "list_decisions"
    kind = ToolKind.READ
    description = (
        "Recent decisions for this application, newest first, with a summary. Filter by "
        "client_id, device_id, factor code, risk level or label. At most 50 per call."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "client_id": _str(),
            "device_id": _str(max_length=100),
            "factor": _str(max_length=80),
            "level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "label": {"type": "string", "enum": ["fraud", "legit"]},
            "days": {"type": "integer", "minimum": 1, "maximum": 365},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            "offset": {"type": "integer", "minimum": 0, "maximum": 10000},
        },
        "additionalProperties": False,
    }

    @classmethod
    def run(cls, inputs, context):
        from core.services.list_decisions import ListDecisions

        filters = Struct(
            days=inputs.get("days", 30), level=inputs.get("level"), label=inputs.get("label"),
            limit=inputs.get("limit", 25), offset=inputs.get("offset", 0),
            application=context.application, factor=inputs.get("factor"),
            client_id=inputs.get("client_id"), device_id=inputs.get("device_id"), unlabelled=False,
        )
        result = ListDecisions.call(application=context.application, filters=filters)
        return sanitize(result)


class DecisionDetailTool(Tool):
    name = "decision_detail"
    kind = ToolKind.READ
    description = (
        "One decision in full: every factor with its weight and score, the thresholds in "
        "force, degraded rules, policy matches, the block streak at the time, the shadow "
        "findings, what the decision hook said, and the label if a person gave one."
    )
    input_schema = {
        "type": "object",
        "properties": {"audit_id": _str(max_length=40)},
        "required": ["audit_id"],
        "additionalProperties": False,
    }

    @classmethod
    def run(cls, inputs, context):
        from core.models import AuditLog

        if not _looks_like_uuid(inputs["audit_id"]):
            raise ToolError("audit_id must be a UUID")
        log = AuditLog.objects.filter(id=inputs["audit_id"], application_id=context.application.id).first()
        if log is None:
            raise ToolError("No such decision for this application")
        return decision_facts(log)


def decision_facts(log):
    ctx = log.context or {}
    return sanitize(dict(
        audit_id=str(log.id),
        when=iso(log.timestamp),
        category=log.category,
        action=log.action,
        client_id=log.actor_id,
        event_id=log.resource_id,
        ip_address=log.ip_address,
        client_class=client_class(log.user_agent),
        has_device=bool(log.device_fingerprint),
        device_id=ctx.get("device_id"),
        risk_score=log.risk_score,
        risk_level=ctx.get("risk_level"),
        should_block=ctx.get("should_block"),
        should_review=ctx.get("should_review"),
        should_challenge=ctx.get("should_challenge"),
        enforcement=ctx.get("enforcement"),
        factors=ctx.get("factors") or [dict(code=c) for c in (log.risk_factors or [])],
        thresholds=ctx.get("thresholds"),
        degraded=ctx.get("degraded"),
        disabled_rules=ctx.get("disabled_rules"),
        policy_matches=ctx.get("policy_matches"),
        block_streak=ctx.get("block_streak"),
        shadow=ctx.get("shadow"),
        hook=ctx.get("hook"),
        amount=ctx.get("amount"),
        currency=ctx.get("currency_code"),
        email=redact_email(ctx.get("email_root")) if ctx.get("email_root") else None,
        outcome=log.outcome,
        label=log.label,
        labeled_at=iso(log.labeled_at),
        hard_blocks=[c for c in (log.risk_factors or []) if c in ("sanctioned_address", "policy_block")],
    ))


class SessionTimelineTool(Tool):
    name = "session_timeline"
    kind = ToolKind.READ
    description = (
        "The session for one origin (a device, else an IP) over a window: its cadence "
        "features (burst ratio, think gaps, adaptive retries, agent clients, rate limits), "
        "accounts touched, motifs, and the ordered events as shape (action, account, "
        "client class, blocked). This is how an agent-driven session is told from a person's."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "device_id": _str(max_length=100),
            "ip_address": _str(max_length=64),
            "window_minutes": {"type": "integer", "minimum": 5, "maximum": 1440},
        },
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        if inputs.get("device_id"):
            return f"device:{inputs['device_id']}"
        return f"ip:{inputs.get('ip_address', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.models import DeviceIdentity
        from core.services.session_activity import SessionActivity, SessionBaseline

        fingerprint = None
        if inputs.get("device_id"):
            fingerprint = (
                DeviceIdentity.objects.filter(id=inputs["device_id"]).values_list("external_id", flat=True).first()
                if _looks_like_uuid(inputs["device_id"]) else inputs["device_id"]
            )
        profile = SessionActivity.load(
            application=context.application, device_fingerprint=fingerprint,
            ip_address=inputs.get("ip_address"), window_minutes=inputs.get("window_minutes"), now=context.now,
        )
        if profile is None:
            raise ToolError("Give a device_id or an ip_address")

        events = []
        for event in list(profile.events)[:80]:
            event = dict(event)
            event["client_class"] = client_class(event.pop("user_agent", None)) if "user_agent" in event else event.get("client_family")
            events.append(event)

        baseline = None
        try:
            baseline = SessionBaseline.load(application=context.application)
        except Exception:
            pass

        return sanitize(dict(
            origin=dict(kind=profile.origin["key"]),
            features=profile.features(),
            baseline=baseline if isinstance(baseline, dict) else getattr(baseline, "__dict__", None),
            events=events,
        ))


class NetworkReputationTool(Tool):
    name = "network_reputation"
    kind = ToolKind.READ
    description = (
        "What other applications in the protection network have confirmed about the "
        "identity keys behind an account: how many applications, confirmed fraud count, "
        "failed challenges, last fraud. Counts only; never another merchant's data."
    )
    input_schema = {
        "type": "object",
        "properties": {"client_id": _str()},
        "required": ["client_id"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return f"client_id:{inputs.get('client_id', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.models import IdentityAccountLink
        from core.services.network_reputation import NetworkReputation

        key_ids = list(
            IdentityAccountLink.objects
            .filter(application=context.application, client_id=inputs["client_id"])
            .values_list("identity_key_id", flat=True)[:50]
        )
        verdict = NetworkReputation.lookup(identity_key_ids=key_ids, application=context.application)
        return sanitize(dict(
            identity_keys=len(key_ids),
            reads_network=bool(getattr(context.application, "reads_network", False)),
            reportable=verdict.is_reportable,
            severity=verdict.severity,
            **verdict.as_context(),
        ))


class SanctionsCheckTool(Tool):
    name = "sanctions_check"
    kind = ToolKind.READ
    description = (
        "Whether a digital-currency address is on the sanctions list FLIT holds, and the "
        "state of that list (loaded, version, age). A hit is a control: it is never cleared."
    )
    input_schema = {
        "type": "object",
        "properties": {"address": _str(max_length=128)},
        "required": ["address"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return f"wallet:{inputs.get('address', '')}"

    @classmethod
    def run(cls, inputs, context):
        from core.intelligence.sanctions import SanctionsList

        addresses = SanctionsList.current()
        status = SanctionsList.status() if hasattr(SanctionsList, "status") else {}
        address = inputs["address"].strip()
        return sanitize(dict(
            address=address,
            sanctioned=address in addresses or address.lower() in addresses,
            list_loaded=bool(addresses),
            list_status=status,
        ))


class SimulatePolicyTool(Tool):
    name = "simulate_policy"
    kind = ToolKind.READ
    description = (
        "Re-score the last N days of decisions under different thresholds or weights and "
        "report what would change: blocks, reviews, recall and false positives against the "
        "labels on record. Use before proposing any policy change."
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
            "days": {"type": "integer", "minimum": 1, "maximum": 90},
        },
        "additionalProperties": False,
    }

    @classmethod
    def run(cls, inputs, context):
        from core.services.simulate_policy import SimulatePolicy

        weights = inputs.get("weights")
        if weights is not None:
            if not all(isinstance(v, (int, float)) and 0 <= v <= 1 for v in weights.values()):
                raise ToolError("weights must be numbers between 0 and 1")
        result = SimulatePolicy.call(
            application=context.application, weights=weights,
            thresholds=inputs.get("thresholds"), days=inputs.get("days", 30),
        )
        return sanitize(result)


class CaseReadTool(Tool):
    name = "case_read"
    kind = ToolKind.READ
    description = (
        "A case: its status, priority, campaign key kind, decision count, the triage "
        "proposal if any, the decisions behind it, and how many analyst notes it carries. "
        "Note text is not shown; it is written by people and may quote an attacker."
    )
    input_schema = {
        "type": "object",
        "properties": {"case_id": _str(max_length=40)},
        "required": ["case_id"],
        "additionalProperties": False,
    }

    @classmethod
    def subject(cls, inputs):
        return f"case:{inputs.get('case_id', '')}"

    @classmethod
    def run(cls, inputs, context):
        case = _case(inputs["case_id"], context)
        decisions = list(case.decisions().order_by("-timestamp")[:25]) if case.campaign_key else [case.audit_log]
        return sanitize(dict(
            case_id=str(case.id),
            status=case.status,
            priority=case.priority,
            origin_kind=(case.campaign_key or "").split(":", 1)[0] or None,
            decision_count=case.decision_count,
            opened_at=iso(case.opened_at),
            last_decision_at=iso(case.last_decision_at),
            closed_at=iso(case.closed_at),
            assignee_set=case.assignee_id is not None,
            triage=case.triage_proposal,
            triage_auto_closed=case.triage_auto_closed,
            notes=case.notes.count(),
            client_id=case.audit_log.actor_id,
            decisions=[decision_facts(d) for d in decisions],
        ))


class PolicyReadTool(Tool):
    name = "policy_read"
    kind = ToolKind.READ
    description = (
        "The decision policy in force for this application: thresholds, weights, explicit "
        "block/review/challenge/allow rules, disabled and shadow rules, the latency budget, "
        "and the organization's ceiling over it."
    )

    @classmethod
    def run(cls, inputs, context):
        from core.services.policy_change import PolicyChange
        return sanitize(PolicyChange.describe(context.application))


class BlockStreakTool(Tool):
    name = "block_streak"
    kind = ToolKind.READ
    description = (
        "The live block counters for an origin: consecutive blocks and total blocks in the "
        "last 24 hours. Give a device_id, else an ip_address, else a client_id."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "device_id": _str(max_length=100),
            "ip_address": _str(max_length=64),
            "client_id": _str(),
        },
        "additionalProperties": False,
    }

    @classmethod
    def run(cls, inputs, context):
        from core.services.block_streak import BlockStreak

        origin = BlockStreak.origin_for(
            device_fingerprint=inputs.get("device_id"), ip_address=inputs.get("ip_address"),
            client_id=inputs.get("client_id"),
        )
        if not origin:
            raise ToolError("Give a device_id, an ip_address or a client_id")
        return dict(origin_kind=origin.split(":", 1)[0], **BlockStreak.read(context.application.id, origin))


class QueueStatsTool(Tool):
    name = "queue_stats"
    kind = ToolKind.READ
    description = (
        "What happened on this application in the last N hours: decisions by action, blocks, "
        "reviews, cases opened and closed, campaigns, the top factors, investigations run, "
        "approvals waiting, monitors fired. The shift brief starts here."
    )
    input_schema = {
        "type": "object",
        "properties": {"hours": {"type": "integer", "minimum": 1, "maximum": 168}},
        "additionalProperties": False,
    }

    @classmethod
    def run(cls, inputs, context):
        from core.models import (
            AuditLog, Case, CaseStatus, Investigation, InvestigationStatus, Monitor, MonitorStatus,
        )
        from core.audit.models import AuditLogCategory

        hours = inputs.get("hours", 12)
        since = context.now - timedelta(hours=hours)
        app = context.application

        decisions = AuditLog.objects.filter(
            application_id=app.id, timestamp__gte=since,
        ).exclude(category__in=[AuditLogCategory.SECURITY, AuditLogCategory.POLICY, AuditLogCategory.SYSTEM])
        blocked = decisions.filter(context__should_block=True).count()
        reviewed = decisions.filter(context__should_review=True).count()

        factor_counts = {}
        for factors in decisions.values_list("risk_factors", flat=True)[:5000]:
            for code in factors or []:
                factor_counts[code] = factor_counts.get(code, 0) + 1
        top_factors = sorted(factor_counts.items(), key=lambda item: -item[1])[:12]

        cases = Case.objects.filter(application=app)
        security = AuditLog.objects.filter(
            application_id=app.id, timestamp__gte=since, category=AuditLogCategory.SECURITY,
        )

        return sanitize(dict(
            hours=hours,
            since=iso(since),
            decisions=decisions.count(),
            by_action=dict(decisions.values_list("action").annotate(n=Count("id")).values_list("action", "n")),
            blocked=blocked,
            reviewed=reviewed,
            top_factors=[dict(code=code, count=count) for code, count in top_factors],
            cases_opened=cases.filter(opened_at__gte=since).count(),
            cases_closed=cases.filter(closed_at__gte=since).count(),
            cases_open_now=cases.filter(status=CaseStatus.OPEN).count(),
            campaigns_active=cases.filter(status=CaseStatus.OPEN, decision_count__gte=3).count(),
            high_priority_open=cases.filter(status=CaseStatus.OPEN, priority="high").count(),
            rate_limited=security.filter(action="rate_limited").count(),
            policy_changes=AuditLog.objects.filter(
                application_id=app.id, timestamp__gte=since, category=AuditLogCategory.POLICY,
            ).count(),
            investigations=Investigation.objects.filter(application=app, created_at__gte=since).count(),
            approvals_waiting=Investigation.objects.filter(
                application=app, status=InvestigationStatus.AWAITING_APPROVAL,
            ).count(),
            monitors_fired=Monitor.objects.filter(application=app, fired_at__gte=since).count(),
            monitors_active=Monitor.objects.filter(application=app, status=MonitorStatus.ACTIVE).count(),
        ))


class RecallMemoryTool(Tool):
    name = "recall_memory"
    kind = ToolKind.READ
    description = (
        "Search what this organization has remembered: facts about its estate, analyst "
        "feedback on rules, past campaigns, references. Returns up to 10 memories ranked by "
        "match, each marked confirmed or unconfirmed and with its age. A memory is a "
        "point-in-time observation, not live state."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "query": _str(max_length=200),
            "kind": {"type": "string", "enum": ["fact", "feedback", "campaign", "reference"]},
        },
        "required": ["query"],
        "additionalProperties": False,
    }

    @classmethod
    def run(cls, inputs, context):
        from core.agent.memory import Memory
        memories = Memory.recall(
            organization=context.organization, application=context.application,
            query=inputs["query"], kind=inputs.get("kind"), limit=10,
        )
        return dict(memories=[Memory.render(m) for m in memories])


def _case(case_id, context):
    from core.models import Case
    if not _looks_like_uuid(case_id):
        raise ToolError("case_id must be a UUID")
    case = Case.objects.filter(id=case_id, application=context.application).select_related("audit_log").first()
    if case is None:
        raise ToolError("No such case for this application")
    return case


def _looks_like_uuid(value):
    from devkit.checks import is_uuid_str
    return is_uuid_str(str(value))


READ_TOOLS = (
    DescribeAccountTool, DescribeDeviceTool, ListDecisionsTool, DecisionDetailTool,
    SessionTimelineTool, NetworkReputationTool, SanctionsCheckTool, SimulatePolicyTool,
    CaseReadTool, PolicyReadTool, BlockStreakTool, QueueStatsTool, RecallMemoryTool,
)
