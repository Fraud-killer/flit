import asyncio
from typing import Optional
from core.audit import rules
from devkit.struct import Struct
from core.audit.scope import Scope
from core.scoring import RiskEngine, RiskLevel
from core.realtime.alerts import AlertManager, Alert, AlertLevel, AlertCategory


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
    )

    @classmethod
    async def audit(
        cls,
        event,
        policy,
        *,
        send_alerts: bool = True,
        include_historical: bool = True,
    ):
        active_rules = list()
        scope = Scope()

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
            client_id = getattr(event, "client_id", None)
            device_fingerprint = getattr(event, "device_fingerprint", None)

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
            historical_risk_scores=historical_scores,
            device_trust_score=device_trust_score,
        )

        if send_alerts and risk_result.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            await cls._send_risk_alert(event, policy, risk_result, reasons)

        return Struct(
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
    async def _send_risk_alert(cls, event, policy, risk_result, reasons):
        client_id = getattr(event, "client_id", None)
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
