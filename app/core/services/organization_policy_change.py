"""
Changing an organization's policy. Only an owner reaches this, so there is no
one to refuse; what matters is that the change is on the record, and that a
loosening says so.
"""

import logging

from core.audit.logger import AuditLogger
from core.audit.models import AuditLogCategory, AuditLogLevel
from core.decision import normalize_rules


logger = logging.getLogger(__name__)


class OrganizationPolicyChange:
    @classmethod
    def snapshot(cls, policy):
        return dict(
            rules=normalize_rules(policy.rules),
            max_block_at=policy.max_block_at,
            max_review_at=policy.max_review_at,
            required_enforcement=policy.required_enforcement,
            disabled_rules=sorted(policy.disabled_rules or []),
        )

    @classmethod
    def apply(cls, *, policy, changes, actor=None):
        before = cls.snapshot(policy)

        if "rules" in changes:
            policy.rules = normalize_rules(changes["rules"])
        for key in ("max_block_at", "max_review_at", "required_enforcement", "disabled_rules"):
            if key in changes:
                setattr(policy, key, changes[key])
        policy.save()

        after = cls.snapshot(policy)
        loosened = cls.loosenings(before, after)
        cls.record(policy, actor, changes, loosened)
        return loosened

    @classmethod
    def loosenings(cls, before, after):
        found = []
        for key in ("max_block_at", "max_review_at"):
            b, a = before[key], after[key]
            if b is not None and (a is None or a > b):
                found.append(f"{key} raised {b} -> {a}")
        if before["required_enforcement"] == "enforcing" and after["required_enforcement"] != "enforcing":
            found.append("required enforcement lifted")
        for action in ("block", "review", "challenge"):
            for entry in before["rules"][action]:
                if entry not in after["rules"][action]:
                    found.append(f"{action} rule removed: {entry.get('subject')}={entry.get('pattern')}")
        for entry in after["rules"]["allow"]:
            if entry not in before["rules"]["allow"]:
                found.append(f"allow rule added: {entry.get('subject')}={entry.get('pattern')}")
        for name in set(after["disabled_rules"]) - set(before["disabled_rules"]):
            found.append(f"rule disabled: {name}")
        return found

    @classmethod
    def record(cls, policy, actor, changes, loosened):
        try:
            AuditLogger.log(
                level=AuditLogLevel.WARNING if loosened else AuditLogLevel.INFO,
                category=AuditLogCategory.POLICY,
                action="organization_policy_loosened" if loosened else "organization_policy_updated",
                actor_type="user",
                actor_id=str(getattr(getattr(actor, "entity", None), "id", "")) or None,
                resource_type="organization_policy",
                resource_id=str(policy.id),
                organization_id=policy.organization_id,
                context=dict(changes=changes, loosened=loosened),
                outcome="applied",
            )
        except Exception:
            logger.exception("Could not record organization policy change")

    @classmethod
    def describe(cls, policy):
        return dict(organization_id=str(policy.organization_id), **cls.snapshot(policy))
