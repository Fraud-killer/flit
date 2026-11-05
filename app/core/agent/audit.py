"""
Everything the agent does goes on the chain.

An investigation's start and end, and every tool call that ran, was proposed,
was denied or waited for a person, is an AuditLog row in the security
category with the agent as actor, the inputs as a digest, the prompt version,
the permission decision and its source. The chain is what a regulator reads;
the Investigation rows are what an analyst reads.
"""

import json
import hashlib
import logging

from core.audit.logger import AuditLogger
from core.audit.models import AuditLogLevel, AuditLogCategory


logger = logging.getLogger(__name__)


class AgentAudit:
    @staticmethod
    def inputs_hash(inputs):
        encoded = json.dumps(inputs or {}, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def investigation(cls, investigation, action, *, outcome, extra=None):
        """`agent_investigation_started|completed|failed|cancelled`."""
        context = dict(
            investigation_id=str(investigation.id), playbook=investigation.playbook,
            trigger=investigation.trigger, mode=investigation.mode, model=investigation.model,
            prompt_version=investigation.prompt_version, cost_usd=round(investigation.cost_usd, 6),
            turns=investigation.turns,
        )
        if extra:
            context.update(extra)
        return cls._log(investigation, f"agent_investigation_{action}", outcome=outcome, context=context,
                        level=AuditLogLevel.WARNING if action == "failed" else AuditLogLevel.INFO)

    @classmethod
    def step(cls, investigation, step):
        """One tool call, whatever became of it."""
        context = dict(
            investigation_id=str(investigation.id), step=step.index, tool=step.tool,
            subject=step.subject, inputs_sha256=cls.inputs_hash(step.inputs),
            decision=step.decision, decision_source=step.decision_source,
            status=step.status, prompt_version=investigation.prompt_version,
            hook=(step.hook or {}).get("outcome") if isinstance(step.hook, dict) else None,
            verifier=(step.verifier or {}).get("verdict") if isinstance(step.verifier, dict) else None,
            output_sha256=step.output_sha256 or None,
        )
        level = AuditLogLevel.WARNING if step.status in ("denied", "rejected", "failed") else AuditLogLevel.INFO
        entry = cls._log(investigation, "agent_action", outcome=step.status, context=context, level=level,
                         resource_type="investigation_step", resource_id=str(step.id))
        if entry is not None:
            step.audit_log_id = entry.id
            step.save(update_fields=["audit_log_id"])
        return entry

    @classmethod
    def _log(cls, investigation, action, *, outcome, context, level, resource_type="investigation", resource_id=None):
        try:
            return AuditLogger.log(
                level=level,
                category=AuditLogCategory.SECURITY,
                action=action,
                actor_type="agent",
                actor_id=f"agent:{investigation.model or 'unknown'}",
                resource_type=resource_type,
                resource_id=resource_id or str(investigation.id),
                application_id=investigation.application_id,
                organization_id=getattr(investigation.application, "organization_id", None),
                context=context,
                outcome=outcome,
            )
        except Exception:
            logger.exception("Could not record agent audit row")
            return None
