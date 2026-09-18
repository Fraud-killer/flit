import asyncio
import logging
from typing import Optional
from asgiref.sync import sync_to_async
from core.audit import rules
from devkit.struct import Struct
from core.audit.scope import Scope
from core.scoring import RiskEngine, RiskLevel
from core.audit.recorder import AuditRecorder
from core.audit.rules.visit_signals import fetch_event_visit
from core.services.resolve_device_identity import ResolveDeviceIdentity
from core.realtime.alerts import AlertManager, Alert, AlertLevel, AlertCategory


logger = logging.getLogger(__name__)


class Auditor:
    rule_classes = (
        # Device & Identity Rules
        rules.DeviceExpiredRule,
        rules.NewDeviceCountryRule,
        rules.UnregisteredDeviceRule,
        # Transaction & Compliance Rules
        rules.AmlCftLimitExceededRule,
        rules.MaximumSingleDebitExceededRule,
        rules.MaximumSingleCreditExceededRule,
        rules.MaximumCumulativeBalanceExceededRule,
        rules.MaximumDailyCumulativeDebitExceededRule,
        rules.VelocityCheckRule,
        rules.ImpossibleTravelRule,
        rules.AccountTakeoverRule,
        # Payment Fraud Rules (Data-Driven)
        rules.PaymentFraudRule,
        rules.GatewayPatternRule,
        rules.CardTestingRule,
        rules.IPConcentrationRule,
        # New Rules from Big Dataset Analysis
        rules.ThreeDSTimeoutRule,
        rules.FakeAddressRule,
        rules.RetryAttackRule,
        rules.IssuerSignalRule,
        # IP & Bot Intelligence Rules
        rules.IPReputationRule,
        rules.BotSignalRule,
        # Device Graph Rules
        rules.MultiAccountingRule,
        rules.AccountSharingRule,
        rules.DeviceTamperingRule,
        rules.DeviceConsistencyRule,
        # Money Mule Rules
        rules.PassThroughRule,
        rules.StructuringRule,
        rules.DormantAwakeningRule,
        rules.AccountFarmingRule,
        rules.MuleNetworkRule,
    )

    @classmethod
    async def audit(
        cls,
        event,
        policy,
        *,
        send_alerts: bool = True,
        include_historical: bool = True,
        record: bool = True,
        device_identity=None,
    ):
        active_rules = list()
        scope = Scope()
        # A caller that already knows the device (a replay of historical
        # data, say) passes it in; otherwise it comes from the visit.
        scope.device_identity = device_identity or await cls._resolve_device_identity(
            event, policy, scope,
        )
        scope.account_activity = await cls._load_account_activity(event, policy)

        for rule_class in cls.rule_classes:
            rule = rule_class(event=event, policy=policy, scope=scope)
            if rule.applies:
                active_rules.append(rule)

        reasons = list()
        rule_tasks = [rule.execute(False) for rule in active_rules]

        for rule_task in asyncio.as_completed(rule_tasks):
            messages = await rule_task
            reasons.extend(messages)

        rule_names = [rule.__class__.__name__ for rule in active_rules]

        risk_engine = RiskEngine()

        message_dicts = [
            {
                "code": msg.code,
                "text": msg.text,
                "context": msg.context,
            }
            for msg in reasons
        ]

        historical_scores = None
        device_trust_score = None

        if include_historical:
            client_id = event.account_id
            device_fingerprint = (
                scope.device_identity.external_id
                if scope.device_identity else None
            )

            if client_id:
                historical_scores = await risk_engine.get_historical_scores(
                    actor_id=client_id,
                    application_id=policy.application.id,
                )

            if device_fingerprint:
                device_trust_score = await risk_engine.get_device_trust_score(
                    device_fingerprint=device_fingerprint,
                    application_id=policy.application.id,
                )

        event_category = "transaction"
        if hasattr(event, "event_type"):
            event_category = event.event_type

        risk_result = risk_engine.calculate_risk(
            message_dicts,
            event_category=event_category,
            account_age_days=getattr(event, "account_age_days", None) or None,
            historical_risk_scores=historical_scores,
            device_trust_score=device_trust_score,
        )

        if send_alerts and risk_result.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            await cls._send_risk_alert(event, policy, risk_result, reasons)

        audit_log = None
        if record:
            audit_log = await AuditRecorder.record(
                event=event,
                policy=policy,
                scope=scope,
                risk_result=risk_result,
                rule_names=rule_names,
            )

        return Struct(
            audit_id=str(audit_log.id) if audit_log else None,
            device_id=str(scope.device_identity.id) if scope.device_identity else None,
            risk_score=risk_result.total_score,
            risk_level=risk_result.level.value,
            rules=rule_names,
            reasons=reasons,
            should_block=risk_result.should_block,
            should_review=risk_result.should_review,
            recommendation=risk_result.recommendation,
            confidence=risk_result.confidence,
            factors=[f.code for f in risk_result.factors],
        )

    @classmethod
    async def _resolve_device_identity(cls, event, policy, scope):
        visit = await fetch_event_visit(event, scope, cls.__name__)
        if visit is None:
            return None

        try:
            return await sync_to_async(ResolveDeviceIdentity.call)(
                visit=visit,
                application=policy.application,
                client_id=event.account_id,
            )
        except Exception:
            logger.exception("Could not resolve device identity")
            return None

    @classmethod
    async def _load_account_activity(cls, event, policy):
        from core.services.account_activity import AccountActivity

        if not event.account_id:
            return None

        try:
            return await sync_to_async(AccountActivity.load)(
                application=policy.application,
                client_id=event.account_id,
            )
        except Exception:
            logger.exception("Could not load account activity")
            return None

    @classmethod
    async def _send_risk_alert(cls, event, policy, risk_result, reasons):
        client_id = event.account_id
        application_id = str(policy.application.id)

        alert_level = AlertLevel.WARNING
        if risk_result.level == RiskLevel.CRITICAL:
            alert_level = AlertLevel.CRITICAL

        high_risk_codes = [f.code for f in risk_result.factors if f.weight >= 0.7]

        alert = Alert(
            level=alert_level,
            category=AlertCategory.FRAUD,
            title=f"High Risk Activity Detected",
            message=risk_result.recommendation,
            application_id=application_id,
            actor_id=client_id,
            risk_score=risk_result.total_score,
            context={
                "risk_level": risk_result.level.value,
                "factors": high_risk_codes,
                "should_block": risk_result.should_block,
                "confidence": risk_result.confidence,
            },
        )

        await AlertManager.send_alert(alert)
