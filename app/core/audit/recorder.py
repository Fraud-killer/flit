import logging
from asgiref.sync import sync_to_async
from devkit.checks import is_present

from core.audit.logger import AuditLogger
from core.audit.events import ClientEvent, TransactionEvent
from core.audit.models import AuditLogCategory, AuditLogLevel


logger = logging.getLogger(__name__)


SUCCESS_STATUSES = {"success", "succeeded", "successful", "approved", "completed"}
FAILURE_STATUSES = {"failed", "failure", "declined", "rejected", "error"}

RISK_LEVEL_TO_LOG_LEVEL = {
    "critical": AuditLogLevel.CRITICAL,
    "high": AuditLogLevel.WARNING,
}


class AuditRecorder:
    """
    Persists every audited event as an AuditLog row. The history is what
    velocity, account takeover, historical scoring and the device graph read.
    """

    @classmethod
    async def record(cls, *, event, policy, scope, risk_result, rule_names):
        try:
            return await sync_to_async(cls.write)(
                event=event,
                policy=policy,
                scope=scope,
                risk_result=risk_result,
                rule_names=rule_names,
            )
        except Exception:
            # Losing one history row is better than failing the decision.
            logger.exception("Could not record audit")
            return None

    @classmethod
    def write(cls, *, event, policy, scope, risk_result, rule_names):
        audit_log = cls.write_log(
            event=event,
            policy=policy,
            scope=scope,
            risk_result=risk_result,
            rule_names=rule_names,
        )

        if risk_result.should_review:
            cls.open_case(audit_log, policy.application)

        return audit_log

    @classmethod
    def open_case(cls, audit_log, application):
        from core.models import Case

        return Case.objects.create(audit_log=audit_log, application=application)

    @classmethod
    def write_log(cls, *, event, policy, scope, risk_result, rule_names):
        application = policy.application
        identity = scope.device_identity

        return AuditLogger.log(
            level=RISK_LEVEL_TO_LOG_LEVEL.get(risk_result.level.value, AuditLogLevel.INFO),
            category=cls.category(event),
            action=cls.action(event),
            actor_type="client",
            actor_id=event.account_id,
            resource_type="transaction" if isinstance(event, TransactionEvent) else "client_event",
            resource_id=cls.value(event, "id"),
            application_id=application.id,
            organization_id=getattr(application, "organization_id", None),
            ip_address=cls.value(event, "ip_address"),
            user_agent=cls.value(event, "user_agent"),
            device_fingerprint=identity.external_id if identity else None,
            risk_score=risk_result.total_score,
            risk_factors=[factor.code for factor in risk_result.factors],
            outcome=cls.outcome(event),
            context=dict(
                visit_id=cls.value(event, "visit_id"),
                device_id=str(identity.id) if identity else None,
                amount=cls.value(event, "amount"),
                currency_code=cls.value(event, "currency_code"),
                risk_level=risk_result.level.value,
                recommendation=risk_result.recommendation,
                should_block=risk_result.should_block,
                rules=rule_names,
                # Kept so a simulation can re-score this decision under
                # different weights without re-running the rules.
                factors=[
                    dict(code=factor.code, weight=factor.weight, score=factor.score)
                    for factor in risk_result.factors
                ],
            ),
        )

    @staticmethod
    def value(event, name):
        value = getattr(event, name, None)
        return value if is_present(value) else None

    @classmethod
    def category(cls, event):
        if isinstance(event, ClientEvent):
            return AuditLogCategory.AUTHENTICATION
        return AuditLogCategory.TRANSACTION

    @classmethod
    def action(cls, event):
        if isinstance(event, ClientEvent):
            return cls.value(event, "action") or "client_event"
        return f"transaction_{cls.value(event, 'type') or 'unknown'}"

    @staticmethod
    def outcome(event):
        status = str(event.extra.get("status", "")).lower()
        if status in SUCCESS_STATUSES:
            return "success"
        if status in FAILURE_STATUSES:
            return "failure"
        return None
