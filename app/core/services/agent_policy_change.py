"""
Changing what the agent may do, with the direction watched.

The agent's policy is a permission surface. Making it looser (a more permissive
mode, a deny or ask rule removed, an allow rule added, a bigger budget, more
turns, the hook removed, the agent switched on, cases investigated
automatically) is something only a signed-in owner may do; an application key
may only tighten. Every change is on the audit chain, and a loosening says so.
"""

import logging

from core.audit.logger import AuditLogger
from core.audit.models import AuditLogLevel, AuditLogCategory
from core.models.agent import AgentMode


logger = logging.getLogger(__name__)

FIELDS = (
    "enabled", "mode", "allow", "ask", "deny", "auto_rules", "hook_url", "hook_timeout_ms",
    "max_cost_usd", "daily_budget_usd", "max_turns", "model", "investigate_cases",
)


class AgentPolicyLooseningForbidden(Exception):
    def __init__(self, loosened):
        self.loosened = loosened
        super().__init__(", ".join(loosened))


class AgentPolicyChange:
    @classmethod
    def snapshot(cls, policy):
        return {field: getattr(policy, field) for field in FIELDS}

    @classmethod
    def loosenings(cls, before, after):
        loosened = []
        if not before["enabled"] and after["enabled"]:
            loosened.append("agent switched on")
        if AgentMode.RANK[after["mode"]] > AgentMode.RANK[before["mode"]]:
            loosened.append(f"mode {before['mode']} → {after['mode']}")
        for name in ("deny", "ask"):
            removed = set(before[name] or []) - set(after[name] or [])
            if removed:
                loosened.append(f"{name} rules removed: {', '.join(sorted(removed))}")
        added = set(after["allow"] or []) - set(before["allow"] or [])
        if added:
            loosened.append(f"allow rules added: {', '.join(sorted(added))}")
        for name in ("max_cost_usd", "daily_budget_usd", "max_turns"):
            if (after[name] or 0) > (before[name] or 0):
                loosened.append(f"{name} raised")
        if before["hook_url"] and not after["hook_url"]:
            loosened.append("hook removed")
        if not before["investigate_cases"] and after["investigate_cases"]:
            loosened.append("cases investigated automatically")
        if (before["auto_rules"] or "").strip() and not (after["auto_rules"] or "").strip():
            loosened.append("standing instructions removed")
        return loosened

    @staticmethod
    def is_owner(actor, organization):
        if actor is None or not getattr(actor, "is_user", False):
            return False
        user = actor.entity
        return getattr(user, "is_staff", False) or organization.owner_id == user.id

    @classmethod
    def apply(cls, *, policy, changes, actor=None, organization):
        before = cls.snapshot(policy)
        after = dict(before, **{k: v for k, v in changes.items() if k in FIELDS})

        loosened = cls.loosenings(before, after)
        if loosened and not cls.is_owner(actor, organization):
            raise AgentPolicyLooseningForbidden(loosened)

        for field, value in after.items():
            setattr(policy, field, value)
        policy.save()
        cls.record(policy, organization, actor, changes, loosened)
        return loosened

    @classmethod
    def record(cls, policy, organization, actor, changes, loosened):
        try:
            AuditLogger.log(
                level=AuditLogLevel.WARNING if loosened else AuditLogLevel.INFO,
                category=AuditLogCategory.POLICY,
                action="agent_policy_loosened" if loosened else "agent_policy_updated",
                actor_type="user" if getattr(actor, "is_user", False) else "application",
                actor_id=str(getattr(getattr(actor, "entity", None), "id", "")) or None,
                resource_type="agent_policy",
                resource_id=str(policy.id),
                application_id=policy.application_id,
                organization_id=organization.id,
                context=dict(changes=changes, loosened=loosened, scope="application" if policy.application_id else "organization"),
                outcome="applied",
            )
        except Exception:
            logger.exception("Could not record agent policy change")

    @classmethod
    def describe(cls, policy, *, organization_policy=None):
        from core.agent.guardrails import AgentGuardrails
        from core.agent.tools import Tools

        data = dict(
            cls.snapshot(policy),
            id=str(policy.id),
            evaluations=policy.evaluations or {},
            tools=[dict(name=t.name, kind=t.kind, needs_verification=t.needs_verification) for t in Tools.registry],
            agent_enabled_globally=AgentGuardrails.enabled_globally(),
        )
        if policy.application_id:
            data["spent_today_usd"] = round(AgentGuardrails.spent_today(policy.application_id), 4)
            data["breaker_tripped_at"] = AgentGuardrails.tripped(policy.application)
            data["organization"] = None if organization_policy is None else dict(
                enabled=organization_policy.enabled, mode=organization_policy.mode,
                deny=organization_policy.deny, ask=organization_policy.ask,
            )
            effective_mode = policy.mode
            if organization_policy is not None:
                effective_mode = AgentMode.tighter(effective_mode, organization_policy.mode)
            data["effective_mode"] = effective_mode
        return data
