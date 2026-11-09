"""
Changing a policy, and knowing which way it moved.

A fraud policy can be edited by whoever holds the application key, and that
key lives on the merchant's servers. If it leaks, the first thing an attacker
does with it is not read decisions — it is raise the block threshold. So the
direction of a change matters more than the change: anyone with the key may
make FLIT stricter, and only a signed-in owner of the organization may make
it looser. Either way the change, and which way it went, is written to the
audit chain.

Loosening means: a threshold raised, a block, review or challenge rule
removed, an allow rule added, a rule disabled, a weight lowered, an outflow
limit raised or removed, or the beneficiary control relaxed.
"""

import logging

from core.audit.logger import AuditLogger
from core.audit.models import AuditLogCategory, AuditLogLevel
from core.decision import ACTIONS, normalize_rules
from core.scoring import DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS


logger = logging.getLogger(__name__)


class PolicyLooseningForbidden(Exception):
    def __init__(self, loosened):
        self.loosened = loosened
        super().__init__("; ".join(loosened))


class PolicyChange:
    @classmethod
    def snapshot(cls, policy):
        calibration = policy.calibration or {}
        thresholds = dict(
            block_at=DEFAULT_THRESHOLDS.block_at,
            review_at=DEFAULT_THRESHOLDS.review_at,
            challenge_at=DEFAULT_THRESHOLDS.challenge_at,
        )
        thresholds.update(calibration.get("thresholds") or {})

        return dict(
            thresholds=thresholds,
            weights=dict(calibration.get("weights") or {}),
            rules=normalize_rules(policy.rules),
            disabled_rules=sorted(policy.disabled_rules or []),
            shadow_rules=sorted(getattr(policy, "shadow_rules", None) or []),
            challenge_method=getattr(policy, "challenge_method", None),
            latency_budget_ms=policy.latency_budget_ms,
            outflow_limits=dict(getattr(policy, "outflow_limits", None) or {}),
            beneficiary_control=dict(getattr(policy, "beneficiary_control", None) or {}),
        )

    @classmethod
    def apply(cls, *, policy, changes, actor=None):
        """Apply `changes` to `policy`; refuse a loosening from an application key."""
        before = cls.snapshot(policy)
        after = cls.snapshot(policy)

        if "thresholds" in changes:
            after["thresholds"].update(changes["thresholds"])
        if "weights" in changes:
            after["weights"].update(changes["weights"])
        if "rules" in changes:
            after["rules"] = normalize_rules(changes["rules"])
        if "disabled_rules" in changes:
            after["disabled_rules"] = sorted(changes["disabled_rules"])
        if "latency_budget_ms" in changes:
            after["latency_budget_ms"] = changes["latency_budget_ms"]
        if "shadow_rules" in changes:
            after["shadow_rules"] = sorted(changes["shadow_rules"])
        if "challenge_method" in changes:
            after["challenge_method"] = changes["challenge_method"]

        if "outflow_limits" in changes:
            after["outflow_limits"] = dict(changes["outflow_limits"] or {})
        if "beneficiary_control" in changes:
            after["beneficiary_control"] = dict(changes["beneficiary_control"] or {})

        loosened = cls.loosenings(before, after)

        if loosened and not cls.is_owner(actor, policy.application):
            raise PolicyLooseningForbidden(loosened)

        calibration = dict(policy.calibration or {})
        calibration["thresholds"] = after["thresholds"]
        calibration["weights"] = after["weights"]
        policy.calibration = calibration
        policy.rules = after["rules"]
        policy.disabled_rules = after["disabled_rules"]
        policy.shadow_rules = after["shadow_rules"]
        policy.challenge_method = after["challenge_method"]
        policy.latency_budget_ms = after["latency_budget_ms"]
        policy.outflow_limits = after["outflow_limits"]
        policy.beneficiary_control = after["beneficiary_control"]
        policy.save(update_fields=[
            "calibration", "rules", "disabled_rules", "shadow_rules", "challenge_method",
            "latency_budget_ms", "outflow_limits", "beneficiary_control", "updated_at",
        ])

        cls.apply_outbound(policy.application, changes)

        cls.record(policy, actor, changes, loosened)

        if loosened:
            from core.outbound import Webhooks
            Webhooks.enqueue(policy.application, "policy.loosened", dict(
                loosened=loosened, changes={k: v for k, v in changes.items() if k != "webhook"},
            ))

        return loosened

    @classmethod
    def loosenings(cls, before, after):
        found = []

        for key in ("block_at", "review_at", "challenge_at"):
            if after["thresholds"][key] > before["thresholds"][key]:
                found.append(f"{key} raised {before['thresholds'][key]} -> {after['thresholds'][key]}")

        for code, value in after["weights"].items():
            previous = before["weights"].get(code, DEFAULT_WEIGHTS.get_weight(code, default=None))
            if previous is not None and value < previous:
                found.append(f"weight {code} lowered {previous} -> {value}")

        for action in ("block", "review", "challenge"):
            removed = [r for r in before["rules"][action] if r not in after["rules"][action]]
            for entry in removed:
                found.append(f"{action} rule removed: {entry.get('subject')}={entry.get('pattern')}")

        added = [r for r in after["rules"]["allow"] if r not in before["rules"]["allow"]]
        for entry in added:
            found.append(f"allow rule added: {entry.get('subject')}={entry.get('pattern')}")

        for name in set(after["disabled_rules"]) - set(before["disabled_rules"]):
            found.append(f"rule disabled: {name}")

        # A rule moved into shadow stops counting: that is a loosening.
        for name in set(after["shadow_rules"]) - set(before["shadow_rules"]):
            found.append(f"rule moved to shadow: {name}")

        found.extend(cls.outflow_loosenings(before["outflow_limits"], after["outflow_limits"]))
        found.extend(cls.beneficiary_loosenings(before["beneficiary_control"], after["beneficiary_control"]))

        return found

    @staticmethod
    def outflow_loosenings(before, after):
        from core.services.outflow_window import FAIL_BLOCK, SCOPE_KEYS

        if not before:
            return []
        if not after:
            return ["outflow limits removed"]

        found = []
        for key in SCOPE_KEYS.values():
            for window, limit in (before.get(key) or {}).items():
                new = (after.get(key) or {}).get(window)
                if new is None:
                    found.append(f"outflow limit removed: {key}.{window}")
                elif new > limit:
                    found.append(f"outflow limit raised: {key}.{window} {limit} -> {new}")

        if before.get("currency") != after.get("currency"):
            found.append("outflow limit currency changed")

        # Any change to the hours moves the tighter limit off some part of the
        # night, so only a lower factor over the same hours counts as tighter.
        hours, new_hours = before.get("off_hours"), after.get("off_hours")
        if hours:
            same = new_hours and all(new_hours.get(k) == hours[k] for k in ("start", "end", "timezone"))
            if not same or new_hours["factor"] > hours["factor"]:
                found.append("outflow off-hours limit relaxed")

        if before.get("fail", FAIL_BLOCK) == FAIL_BLOCK and after.get("fail", FAIL_BLOCK) != FAIL_BLOCK:
            found.append("outflow failure handling relaxed to review")

        return found

    @staticmethod
    def beneficiary_loosenings(before, after):
        from core.services.money_out import DEFAULT_COOLING_HOURS

        if not before.get("enabled"):
            return []
        if not after.get("enabled"):
            return ["beneficiary control turned off"]

        found = []
        hours = before.get("cooling_hours", DEFAULT_COOLING_HOURS)
        new_hours = after.get("cooling_hours", DEFAULT_COOLING_HOURS)
        if new_hours < hours:
            found.append(f"beneficiary cooling period shortened {hours} -> {new_hours}")
        if before.get("fail", "block") == "block" and after.get("fail", "block") != "block":
            found.append("beneficiary failure handling relaxed to review")
        return found

    @staticmethod
    def apply_outbound(application, changes):
        """Webhook and decision-hook settings live on the application."""
        from core import mcrypt

        fields = []

        if "webhook" in changes:
            webhook = changes["webhook"]
            if webhook is None:
                application.webhook_url = None
                application.webhook_secret = None
                application.webhook_events = []
            else:
                application.webhook_url = webhook["url"].strip()
                if webhook.get("secret"):
                    application.webhook_secret = mcrypt.encrypt(webhook["secret"])
                if "events" in webhook and webhook["events"] is not None:
                    application.webhook_events = sorted(set(webhook["events"]))
            fields += ["webhook_url", "webhook_secret", "webhook_events"]

        if "decision_hook" in changes:
            hook = changes["decision_hook"]
            if hook is None:
                application.decision_hook_url = None
            else:
                application.decision_hook_url = hook["url"].strip()
                if hook.get("timeout_ms"):
                    application.decision_hook_timeout_ms = hook["timeout_ms"]
            fields += ["decision_hook_url", "decision_hook_timeout_ms"]

        if fields:
            application.save(update_fields=fields + ["updated_at"])

    @staticmethod
    def is_owner(actor, application):
        if actor is None or not getattr(actor, "is_user", False):
            return False
        user = actor.entity
        return getattr(user, "is_staff", False) or application.organization.owner_id == user.id

    @classmethod
    def record(cls, policy, actor, changes, loosened):
        application = policy.application
        try:
            AuditLogger.log(
                level=AuditLogLevel.WARNING if loosened else AuditLogLevel.INFO,
                category=AuditLogCategory.POLICY,
                action="policy_loosened" if loosened else "policy_updated",
                actor_type="user" if getattr(actor, "is_user", False) else "application",
                actor_id=str(getattr(getattr(actor, "entity", None), "id", "")) or None,
                resource_type="policy",
                resource_id=str(policy.id),
                application_id=application.id,
                organization_id=getattr(application, "organization_id", None),
                context=dict(changes=changes, loosened=loosened),
                outcome="applied",
            )
        except Exception:
            logger.exception("Could not record policy change")

    @classmethod
    def describe(cls, application):
        from core.calibration import engine_for
        from core.models import OrganizationPolicy

        policy = application.policy
        organization_policy = OrganizationPolicy.for_application(application)
        engine = engine_for(policy, organization_policy)
        snapshot = cls.snapshot(policy)

        return dict(
            **snapshot,
            enforcement=application.enforcement,
            webhook=dict(
                url=application.webhook_url,
                secret_configured=bool(application.webhook_secret),
                events=sorted(application.webhook_events or []),
            ) if application.webhook_url else None,
            decision_hook=dict(
                url=application.decision_hook_url,
                timeout_ms=application.decision_hook_timeout_ms,
            ) if application.decision_hook_url else None,
            effective=dict(
                thresholds=dict(
                    block_at=engine.thresholds.block_at,
                    review_at=engine.thresholds.review_at,
                    challenge_at=engine.thresholds.challenge_at,
                ),
                enforcing=application.is_enforcing or bool(
                    organization_policy and organization_policy.requires_enforcing
                ),
            ),
            organization=None if organization_policy is None else dict(
                rules=normalize_rules(organization_policy.rules),
                max_block_at=organization_policy.max_block_at,
                max_review_at=organization_policy.max_review_at,
                required_enforcement=organization_policy.required_enforcement,
                disabled_rules=sorted(organization_policy.disabled_rules or []),
            ),
        )
