import asyncio
import logging
from typing import Optional
from asgiref.sync import sync_to_async
from core.audit import rules
from core.audit.rules.base_rule import FailMode
from devkit.message import Message
from devkit.struct import Struct
from core.audit.scope import Scope
from core.scoring import RiskEngine, RiskLevel
from core.audit.recorder import AuditRecorder
from core.audit.rules.visit_signals import fetch_event_visit
from core.services.resolve_device_identity import ResolveDeviceIdentity
from core.services.resolve_identity_ladder import resolve_identity_ladder
from core.realtime.alerts import AlertManager, Alert, AlertLevel, AlertCategory


logger = logging.getLogger(__name__)


class Auditor:
    # How long the rules may take, all of them together, before the decision
    # is made with what has arrived. Bounded so a hung lookup or a starved
    # database cannot hold a payment open indefinitely. Overridden per
    # application on Policy.latency_budget_ms.
    DEFAULT_LATENCY_BUDGET_MS = 3000

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
        # Signup Surface Rules
        rules.ExpectedSignalRule,
        rules.DisposableEmailRule,
        rules.EmailPatternRule,
        rules.DomainReputationRule,
        # Crypto Rails
        rules.CryptoCashOutRule,
        rules.NewWithdrawalAddressRule,
        rules.CollectionWalletRule,
        rules.FreshFundingWalletRule,
        rules.SanctionedAddressRule,
        # Shared Protection Network
        rules.NetworkReputationRule,
        rules.ChallengeEvasionRule,
        rules.ChallengePassedRule,
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
        # Credential Surface Rules
        rules.ResetToLoginRule,
        rules.AutomatedCredentialActionRule,
        rules.CredentialResetStormRule,
        # Session Shape
        rules.SessionShapeRule,
        # The origin's own recent blocks
        rules.BlockStreakRule,
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

        # Everything below runs on the event loop and reads
        # `policy.application` freely. Load it, and its organization, once
        # here, so a policy that arrived without them cached does not turn
        # into a synchronous query from async code half-way through.
        await cls._warm(policy)

        visit = await fetch_event_visit(event, scope, cls.__name__)
        # A caller that already knows the device (a replay of historical
        # data, say) passes it in; otherwise it comes from the visit.
        scope.device_identity = device_identity or await cls._resolve_device_identity(
            event, policy, scope, visit=visit,
        )
        # Resolved after the device so the device becomes the ladder's top
        # rung when there is one, and before the rules so a rule counting
        # accounts on a key counts this event too.
        scope.identity_ladder = await resolve_identity_ladder(
            event=event, policy=policy, scope=scope,
            visit=visit, device_identity=scope.device_identity,
            write=record,
        )
        scope.account_activity = await cls._load_account_activity(event, policy)

        # The organization's standing instructions, if it has any: rules every
        # application inherits, thresholds none may exceed, rules switched off
        # across the estate.
        organization_policy = await cls._load_organization_policy(policy)
        disabled = cls.disabled_rules(policy, organization_policy)
        shadowed = cls.shadow_rules(policy)

        for rule_class in cls.rule_classes:
            if rule_class.__name__ in disabled:
                continue
            rule = rule_class(event=event, policy=policy, scope=scope)
            if rule.applies:
                active_rules.append(rule)

        # Decisions a person wrote down, read before the rules run: a blocked
        # range, a trusted partner, a step-up for an ASN. The rules still run,
        # so history records what they would have found.
        from core.decision import DecisionRules
        decision_rules = DecisionRules.for_policy(policy, organization_policy)
        facts = DecisionRules.facts(event, scope, visit)
        matches = decision_rules.matches(facts, phase="pre") if decision_rules else None

        reasons, degraded = await cls._run_rules(active_rules, cls.latency_budget(policy))

        # A rule in shadow ran, and its findings are kept — under the
        # decision, not in it. They are what shadow_report measures.
        shadow_findings = []
        if shadowed:
            live = []
            for msg in reasons:
                if msg.context.get("rule") in shadowed:
                    shadow_findings.append(dict(rule=msg.context.get("rule"), code=msg.code, context=msg.context))
                else:
                    live.append(msg)
            reasons = live

        # A cleared step-up presented with the event: spend one replay of it.
        challenge_id = cls.event_value(event, "challenge_id")
        if challenge_id:
            replay = await cls._consume_challenge(policy, event, challenge_id)
            if replay is not None:
                reasons.append(replay)

        # Rules on the codes the rules produced ("block anyone with
        # campaign_motif") are read now that the codes exist.
        if decision_rules:
            facts["factors"] = [msg.code for msg in reasons]
            post = decision_rules.matches(facts, phase="post")
            for action, found in post.items():
                matches[action].extend(found)
            reasons.extend(DecisionRules.messages(matches))

        rule_names = [rule.__class__.__name__ for rule in active_rules]

        # The weights this application has learned from its own outcomes,
        # or the defaults until it has, capped by its organization. Same
        # arithmetic the calibrator and the simulator use, so what they
        # predicted is what this does.
        from core.calibration import engine_for
        risk_engine = engine_for(policy, organization_policy)

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
            coverage=scope.identity_ladder.coverage if scope.identity_ladder else None,
        )

        # The merchant's own logic gets a vote, and may only tighten.
        hook = await cls._consult_hook(policy, event, risk_result, rule_names)

        # The origin's streak: what the decisions before this one said to it.
        # Recorded from the raw decision, so a shadow deployment learns the
        # same streaks an enforcing one would.
        origin = cls.origin(event, scope)
        streak = await cls._record_streak(policy, origin, risk_result.should_block)

        if send_alerts and risk_result.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            await cls._send_risk_alert(event, policy, risk_result, reasons)

        if send_alerts and streak["consecutive"] == cls.CAMPAIGN_ALERT_AT:
            await cls._send_campaign_alert(event, policy, origin, streak)

        audit_log = None
        if record:
            audit_log = await AuditRecorder.record(
                event=event,
                policy=policy,
                scope=scope,
                risk_result=risk_result,
                rule_names=rule_names,
                degraded=degraded,
                disabled=sorted(disabled),
                campaign_key=origin,
                streak=streak,
                shadow=shadow_findings,
                hook=hook,
            )

        # In shadow, `should_block` and `should_challenge` come back false —
        # not merely flagged as unenforced. An integration reads
        # `if (decision.should_block) reject()`, so the field that drives that
        # branch has to be the safe one; anything else means a shadow
        # deployment turns customers away the first time someone forgets to
        # check a second flag. What FLIT actually decided is reported
        # alongside as `would_block`, and it is the decision that gets
        # recorded, so history and the evidence ledger stay honest.
        # Safe default: anything that cannot tell us it is enforcing is
        # treated as shadow, so a misconfiguration suppresses actions rather
        # than taking them.
        application = policy.application
        enforcing = bool(getattr(application, "is_enforcing", False)) or bool(
            organization_policy is not None and organization_policy.requires_enforcing
        )

        # When the policy says so, a decision that asks for a step-up issues
        # it, so the merchant verifies and replays rather than calling twice.
        challenge = None
        if enforcing and risk_result.should_challenge and getattr(policy, "challenge_method", None):
            challenge = await cls._issue_challenge(policy, event, scope, audit_log)

        if send_alerts:
            await cls._notify(policy, event, risk_result, audit_log, origin)

        return Struct(
            audit_id=str(audit_log.id) if audit_log else None,
            device_id=str(scope.device_identity.id) if scope.device_identity else None,
            identity=scope.identity_ladder.describe() if scope.identity_ladder else None,
            risk_score=risk_result.total_score,
            risk_level=risk_result.level.value,
            rules=rule_names,
            reasons=reasons,
            enforcement=getattr(application, "enforcement", "shadow"),
            should_block=risk_result.should_block and enforcing,
            should_challenge=risk_result.should_challenge and enforcing,
            # Review is internal: a case in a queue costs a reviewer's
            # attention, not a customer's signup, so it happens in shadow too.
            should_review=risk_result.should_review,
            would_block=risk_result.should_block,
            would_challenge=risk_result.should_challenge,
            recommendation=risk_result.recommendation,
            confidence=risk_result.confidence,
            coverage=risk_result.coverage,
            factors=[f.code for f in risk_result.factors],
            # Rules that raised or ran out of time, so the caller knows what
            # this decision did not consider. Empty on a complete decision.
            degraded=degraded,
            # Rules switched off by the application or its organization.
            disabled_rules=sorted(disabled),
            # Decisions a person wrote down that fired on this event.
            policy_matches={k: v for k, v in (matches or {}).items() if v},
            # How many blocks in a row this origin has now had.
            block_streak=streak["consecutive"],
            # Findings of rules running in shadow: recorded, not counted.
            shadow=shadow_findings,
            # What the merchant's decision hook said, if one is configured.
            hook=hook,
            # The step-up this decision issued, when the policy issues them.
            # The OTP code appears here once and is never stored.
            challenge=challenge,
        )

    # Consecutive blocks at which one origin becomes a campaign worth a
    # reviewer's attention right now, not in the queue.
    CAMPAIGN_ALERT_AT = 3

    @staticmethod
    def origin(event, scope):
        from core.services.block_streak import BlockStreak

        identity = getattr(scope, "device_identity", None)
        return BlockStreak.origin_for(
            device_fingerprint=identity.external_id if identity else None,
            ip_address=getattr(event, "ip_address", None) if (
                getattr(event, "ip_address", None) not in (None, "")
                and getattr(event, "ip_address", None).__class__ is str
            ) else None,
            client_id=event.account_id,
        )

    @classmethod
    async def _record_streak(cls, policy, origin, blocked):
        from core.services.block_streak import BlockStreak

        try:
            return await sync_to_async(BlockStreak.record)(policy.application.id, origin, blocked)
        except Exception:
            logger.exception("Could not record block streak")
            return dict(consecutive=0, total_24h=0)

    @staticmethod
    async def _warm(policy):
        def touch():
            application = policy.application
            getattr(application, "organization", None)
            return application

        try:
            await sync_to_async(touch)()
        except Exception:
            logger.exception("Could not load the policy's application")

    @classmethod
    async def _load_organization_policy(cls, policy):
        from core.models import OrganizationPolicy

        try:
            return await sync_to_async(OrganizationPolicy.for_application)(policy.application)
        except Exception:
            logger.exception("Could not load organization policy")
            return None

    @staticmethod
    def shadow_rules(policy):
        value = getattr(policy, "shadow_rules", None)
        return set(str(name) for name in value) if isinstance(value, (list, tuple, set)) else set()

    @staticmethod
    def event_value(event, name):
        from devkit.checks import is_present

        value = getattr(event, name, None)
        if not is_present(value):
            value = (getattr(event, "extra", None) or {}).get(name)
        return value if is_present(value) else None

    @classmethod
    async def _consume_challenge(cls, policy, event, challenge_id):
        from core.services.challenge_replay import ChallengeReplay

        try:
            return await sync_to_async(ChallengeReplay.consume)(
                application=policy.application, client_id=event.account_id, challenge_id=str(challenge_id),
            )
        except Exception:
            logger.exception("Could not consume challenge replay")
            return None

    @classmethod
    async def _issue_challenge(cls, policy, event, scope, audit_log):
        from core.services.challenges import IssueChallenge

        try:
            challenge, code = await IssueChallenge.call_async(
                application=policy.application,
                client_id=event.account_id or "anonymous",
                method=policy.challenge_method,
                audit_log=audit_log,
                identity_key_ids=scope.identity_ladder.network_key_ids() if scope.identity_ladder else [],
            )
        except Exception:
            logger.exception("Could not issue challenge")
            return None

        return dict(
            id=str(challenge.id), method=challenge.method, code=code,
            expires_at=challenge.expires_at.isoformat(),
        )

    @classmethod
    async def _consult_hook(cls, policy, event, risk_result, rule_names):
        from core.outbound import DecisionHook

        application = policy.application
        if not getattr(application, "decision_hook_url", None):
            return None

        try:
            return await DecisionHook.consult(
                application=application, event=event, risk_result=risk_result,
                decision=dict(
                    risk_score=risk_result.total_score,
                    risk_level=risk_result.level.value,
                    should_block=risk_result.should_block,
                    should_challenge=risk_result.should_challenge,
                    should_review=risk_result.should_review,
                    factors=[f.code for f in risk_result.factors],
                    rules=rule_names,
                ),
            )
        except Exception:
            logger.exception("Decision hook failed")
            return dict(error="exception", applied=False)

    @classmethod
    async def _notify(cls, policy, event, risk_result, audit_log, origin):
        """Webhooks for the decisions a merchant wants to hear about."""
        from core.outbound import Webhooks

        application = policy.application
        if not getattr(application, "webhook_url", None):
            return

        payload = dict(
            audit_id=str(audit_log.id) if audit_log else None,
            event_id=cls.event_value(event, "id"),
            client_id=event.account_id,
            risk_score=risk_result.total_score,
            risk_level=risk_result.level.value,
            factors=[f.code for f in risk_result.factors],
            recommendation=risk_result.recommendation,
            enforcement=getattr(application, "enforcement", "shadow"),
            origin=origin,
        )

        try:
            if risk_result.should_block:
                await sync_to_async(Webhooks.enqueue)(application, "decision.blocked", payload)
            elif risk_result.should_review:
                await sync_to_async(Webhooks.enqueue)(application, "decision.review", payload)
        except Exception:
            logger.exception("Could not queue decision webhook")

    @staticmethod
    def disabled_rules(policy, organization_policy=None):
        names = set()
        for source in (policy, organization_policy):
            value = getattr(source, "disabled_rules", None)
            if isinstance(value, (list, tuple, set)):
                names.update(str(name) for name in value)
        return names

    @classmethod
    def latency_budget(cls, policy):
        """Seconds the rules may take together, from the policy or the default."""
        value = getattr(policy, "latency_budget_ms", None)

        if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
            value = cls.DEFAULT_LATENCY_BUDGET_MS

        return value / 1000.0

    @classmethod
    async def _run_rules(cls, active_rules, budget_seconds):
        """
        Run every applicable rule concurrently and return (messages, degraded).

        A rule that raises or outlives the budget does not take the decision
        with it. Its absence is recorded as a `rule_unavailable` finding —
        never scored — and listed in `degraded`. Whether that absence also
        sends the decision to review is the rule's own call (see
        BaseRule.fail_mode): a control that did not run fails closed.
        """
        reasons = list()
        degraded = list()

        if not active_rules:
            return reasons, degraded

        tasks = {
            asyncio.ensure_future(rule.execute(False)): rule
            for rule in active_rules
        }

        done, pending = await asyncio.wait(tasks, timeout=budget_seconds)

        for task in pending:
            task.cancel()

        for task, rule in tasks.items():
            name = rule.__class__.__name__

            if task in pending:
                reasons.append(cls._unavailable(rule, "timeout"))
                degraded.append(dict(rule=name, reason="timeout"))
                logger.warning("Rule %s exceeded the latency budget (%.0f ms)", name, budget_seconds * 1000)
                continue

            error = task.exception()
            if error is not None:
                reasons.append(cls._unavailable(rule, "error", error))
                degraded.append(dict(rule=name, reason="error", error=type(error).__name__))
                logger.error("Rule %s failed: %r", name, error, exc_info=error)
                continue

            reasons.extend(task.result())

        return reasons, degraded

    @staticmethod
    def _unavailable(rule, reason, error=None):
        fail_mode = rule.fail_mode()

        return Message(
            code="rule_unavailable",
            text=(
                f"{rule.__class__.__name__} did not run ({reason}); "
                + (
                    "the decision is sent to review because this control did not check"
                    if fail_mode == FailMode.CLOSED
                    else "its findings, if any, are missing from this decision"
                )
            ),
            context=dict(
                rule=rule.__class__.__name__,
                reason=reason,
                error=type(error).__name__ if error is not None else None,
                fail_mode=fail_mode,
                score=0.0,
                force_review=fail_mode == FailMode.CLOSED,
            ),
        )

    @classmethod
    async def _resolve_device_identity(cls, event, policy, scope, visit=None):
        if visit is None:
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
    async def _send_campaign_alert(cls, event, policy, origin, streak):
        organization_id = getattr(policy.application, "organization_id", None)

        await AlertManager.send_alert(Alert(
            level=AlertLevel.CRITICAL,
            category=AlertCategory.FRAUD,
            title="Campaign detected",
            message=(
                f"{origin} has been blocked {streak['consecutive']} times in a row; "
                "a loop is adapting against this application."
            ),
            application_id=str(policy.application.id),
            organization_id=str(organization_id) if organization_id else None,
            actor_id=event.account_id,
            context=dict(origin=origin, **streak, kind="campaign_detected"),
        ))

        from core.outbound import Webhooks
        await sync_to_async(Webhooks.enqueue)(
            policy.application, "campaign.detected",
            dict(origin=origin, client_id=event.account_id, **streak),
        )

    @classmethod
    async def _send_risk_alert(cls, event, policy, risk_result, reasons):
        client_id = event.account_id
        application_id = str(policy.application.id)

        alert_level = AlertLevel.WARNING
        if risk_result.level == RiskLevel.CRITICAL:
            alert_level = AlertLevel.CRITICAL

        high_risk_codes = [f.code for f in risk_result.factors if f.weight >= 0.7]

        organization_id = getattr(policy.application, "organization_id", None)

        alert = Alert(
            level=alert_level,
            category=AlertCategory.FRAUD,
            title=f"High Risk Activity Detected",
            message=risk_result.recommendation,
            application_id=application_id,
            organization_id=str(organization_id) if organization_id else None,
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
