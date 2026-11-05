import logging
from asgiref.sync import sync_to_async
from devkit.checks import is_present

from core.audit.logger import AuditLogger
from core.audit.events import ClientEvent, TransactionEvent, AuthenticationEvent, RegistrationEvent
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
    async def record(cls, *, event, policy, scope, risk_result, rule_names, degraded=None,
                     disabled=None, campaign_key=None, streak=None, shadow=None, hook=None):
        try:
            return await sync_to_async(cls.write)(
                event=event,
                policy=policy,
                scope=scope,
                risk_result=risk_result,
                rule_names=rule_names,
                degraded=degraded,
                disabled=disabled,
                campaign_key=campaign_key,
                streak=streak,
                shadow=shadow,
                hook=hook,
            )
        except Exception:
            # Losing one history row is better than failing the decision.
            logger.exception("Could not record audit")
            return None

    @classmethod
    def write(cls, *, event, policy, scope, risk_result, rule_names, degraded=None,
              disabled=None, campaign_key=None, streak=None, shadow=None, hook=None):
        audit_log = cls.write_log(
            event=event,
            policy=policy,
            scope=scope,
            risk_result=risk_result,
            rule_names=rule_names,
            degraded=degraded,
            disabled=disabled,
            streak=streak,
            shadow=shadow,
            hook=hook,
        )

        if risk_result.should_review:
            cls.open_case(
                audit_log, policy.application,
                campaign_key=campaign_key,
                priority=cls.priority(risk_result, streak),
            )

        return audit_log

    @staticmethod
    def priority(risk_result, streak=None):
        from core.models import CasePriority

        critical = risk_result.level.value == "critical" or risk_result.should_block
        campaign = (streak or {}).get("consecutive", 0) >= 3
        return CasePriority.HIGH if critical or campaign else CasePriority.NORMAL

    @classmethod
    def open_case(cls, audit_log, application, *, campaign_key=None, priority=None):
        """
        One case per campaign. A decision from an origin that already has an
        open case in the window lands on that case and is counted there,
        instead of opening a new one for the reviewer to find and merge.
        """
        from datetime import timedelta
        from django.utils import timezone
        from core.models import Case, CasePriority, CaseStatus

        priority = priority or CasePriority.NORMAL
        now = timezone.now()

        if campaign_key:
            existing = (
                Case.objects
                .filter(
                    application=application,
                    status=CaseStatus.OPEN,
                    campaign_key=campaign_key,
                    opened_at__gte=now - timedelta(hours=Case.CAMPAIGN_WINDOW_HOURS),
                )
                .order_by("-opened_at")
                .first()
            )
            if existing is not None:
                existing.decision_count += 1
                existing.last_decision_at = now
                if CasePriority.ORDER[priority] < CasePriority.ORDER[existing.priority]:
                    existing.priority = priority
                existing.save(update_fields=["decision_count", "last_decision_at", "priority"])
                return existing

        case = Case.objects.create(
            audit_log=audit_log, application=application,
            campaign_key=campaign_key, priority=priority, last_decision_at=now,
        )

        from core.outbound import Webhooks
        Webhooks.enqueue(application, "case.opened", dict(
            case_id=str(case.id), audit_id=str(audit_log.id), client_id=audit_log.actor_id,
            priority=priority, campaign_key=campaign_key, risk_score=audit_log.risk_score,
            factors=audit_log.risk_factors,
        ))

        return case

    @classmethod
    def write_log(cls, *, event, policy, scope, risk_result, rule_names, degraded=None,
                  disabled=None, streak=None, shadow=None, hook=None):
        application = policy.application
        identity = scope.device_identity

        return AuditLogger.log(
            level=RISK_LEVEL_TO_LOG_LEVEL.get(risk_result.level.value, AuditLogLevel.INFO),
            category=cls.category(event),
            action=cls.action(event),
            actor_type="client",
            actor_id=event.account_id,
            resource_type=cls.resource_type(event),
            resource_id=cls.value(event, "id"),
            application_id=application.id,
            organization_id=getattr(application, "organization_id", None),
            ip_address=cls.value(event, "ip_address"),
            user_agent=cls.value(event, "user_agent"),
            device_fingerprint=identity.external_id if identity else None,
            risk_score=risk_result.total_score,
            risk_factors=[factor.code for factor in risk_result.factors],
            outcome=cls.outcome(event),
            context=cls.cap(dict(
                visit_id=cls.value(event, "visit_id"),
                device_id=str(identity.id) if identity else None,
                # Credential actions: what was done and how the credential
                # was presented, so the takeover rules can read the sequence
                # back without re-parsing the event.
                action=cls.value(event, "action"),
                auth_method=cls.value(event, "auth_method"),
                second_factor=cls.value(event, "second_factor"),
                amount=cls.value(event, "amount"),
                currency_code=cls.value(event, "currency_code"),
                transaction_type=cls.value(event, "type"),
                counterparty_id=cls.value(event, "counterparty_id"),
                card_fingerprint=cls.value(event, "card_fingerprint"),
                # Crypto movement, recorded as the normalised correlation key
                # rather than the raw address, so history compares the way the
                # identity ladder does.
                chain=cls.value(event, "chain"),
                asset=cls.value(event, "asset"),
                counterparty_key=cls.counterparty_key(event),
                risk_level=risk_result.level.value,
                recommendation=risk_result.recommendation,
                # The decision FLIT reached, not what it was allowed to do
                # with it: a shadow run has to produce the same history an
                # enforcing one would, or measuring it later is meaningless.
                should_block=risk_result.should_block,
                should_challenge=risk_result.should_challenge,
                should_review=risk_result.should_review,
                enforcement=getattr(application, "enforcement", "shadow"),
                coverage=risk_result.coverage,
                rules=rule_names,
                # Rules that did not run, so a later reader knows this
                # decision was made on less than the full set.
                degraded=degraded or [],
                disabled_rules=disabled or [],
                block_streak=(streak or {}).get("consecutive", 0),
                # Findings of rules in shadow, kept apart from the live ones.
                shadow=[dict(rule=f["rule"], code=f["code"]) for f in (shadow or [])],
                # What the merchant's decision hook said and whether it applied.
                hook=hook,
                # The global identity keys this decision touched. Kept so that
                # labelling it later — a case confirmed, a chargeback
                # reported — can attribute that outcome back to them without
                # re-resolving an event whose signals have since moved on.
                identity_key_ids=(
                    scope.identity_ladder.network_key_ids()
                    if scope.identity_ladder else []
                ),
                # Kept so a simulation can re-score this decision under
                # different weights without re-running the rules.
                factors=[
                    dict(code=factor.code, weight=factor.weight, score=factor.score)
                    for factor in risk_result.factors
                ],
            )),
        )

    @staticmethod
    def counterparty_key(event):
        """The normalised key for where funds were sent, if anywhere."""
        from core.intelligence import wallet_intelligence

        address = AuditRecorder.value(event, "counterparty_address")

        if not address:
            return None

        return wallet_intelligence.address_key(
            address, AuditRecorder.value(event, "chain"),
        )

    # No single value in a decision's context may exceed this. A provider
    # response or browser detail blob the size of a web page is kept as a
    # preview and a digest, not as the row.
    MAX_CONTEXT_VALUE_CHARS = 4000

    @classmethod
    def cap(cls, context):
        """Oversized strings become a preview plus a digest of the whole."""
        import hashlib
        import json

        capped = {}
        for key, value in context.items():
            if isinstance(value, str) and len(value) > cls.MAX_CONTEXT_VALUE_CHARS:
                capped[key] = dict(
                    truncated=True, length=len(value),
                    sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    preview=value[:cls.MAX_CONTEXT_VALUE_CHARS // 4],
                )
            elif isinstance(value, (dict, list)):
                encoded = json.dumps(value, default=str)
                if len(encoded) > cls.MAX_CONTEXT_VALUE_CHARS * 4:
                    capped[key] = dict(
                        truncated=True, length=len(encoded),
                        sha256=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                        preview=encoded[:cls.MAX_CONTEXT_VALUE_CHARS // 4],
                    )
                else:
                    capped[key] = value
            else:
                capped[key] = value
        return capped

    @staticmethod
    def value(event, name):
        """Declared attributes first, then the payment fields in `extra`."""
        value = getattr(event, name, None)

        if not is_present(value):
            value = (getattr(event, "extra", None) or {}).get(name)

        return value if is_present(value) else None

    @classmethod
    def category(cls, event):
        if isinstance(event, (ClientEvent, AuthenticationEvent)):
            return AuditLogCategory.AUTHENTICATION
        return AuditLogCategory.TRANSACTION

    @classmethod
    def resource_type(cls, event):
        if isinstance(event, TransactionEvent):
            return "transaction"
        if isinstance(event, AuthenticationEvent):
            return "authentication"
        return "client_event"

    @classmethod
    def action(cls, event):
        if isinstance(event, AuthenticationEvent):
            return cls.value(event, "action")
        if isinstance(event, ClientEvent):
            return cls.value(event, "action") or "client_event"
        if isinstance(event, RegistrationEvent):
            # Recorded by name so a session can tell the accounts an origin
            # created from the ones it merely touched.
            return cls.value(event, "action") or "registration"
        return f"transaction_{cls.value(event, 'type') or 'unknown'}"

    @staticmethod
    def outcome(event):
        if isinstance(event, AuthenticationEvent):
            return "success" if event.succeeded else "failure"

        status = str(event.extra.get("status", "")).lower()
        if status in SUCCESS_STATUSES:
            return "success"
        if status in FAILURE_STATUSES:
            return "failure"
        return None
