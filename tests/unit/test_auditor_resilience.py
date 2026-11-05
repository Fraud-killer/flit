"""
A decision has a deadline, and a rule cannot take the decision down with it.

Before this, one rule raising turned the whole audit into an HTTP 500, and one
rule hanging held the payment open for as long as the dependency took. An
attacker who can make one lookup slow can make the merchant's checkout slow.
Now a rule that raises or outlives the budget is reported as unavailable and
the decision is made with what arrived.

What that absence means is the rule's own call. A detection that did not run
found nothing. A control that did not run did not check, and a compliance
check that quietly did not happen is worse than one that is absent — so it
sends the decision to review.
"""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest

from devkit.message import Message


def audit(application, event):
    from core.audit.auditor import Auditor

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=None),
    ):
        return asyncio.run(
            Auditor.audit(event, application.policy, send_alerts=False)
        )


def transfer_event(client_id="user_1"):
    from core.audit.events import TransactionEvent

    return TransactionEvent(
        id=f"tx_{time.time()}", type="debit", amount=100,
        currency_code="USD", client_id=client_id,
    )


def with_rules(*extra):
    """The production rule set plus the test rules, for one test."""
    from core.audit.auditor import Auditor

    return patch.object(Auditor, "rule_classes", Auditor.rule_classes + extra)


def budget(application, milliseconds):
    application.policy.latency_budget_ms = milliseconds
    application.policy.save(update_fields=["latency_budget_ms"])


def make_rule(name, *, kind=None, on_failure=None, perform):
    from core.audit.rules.base_rule import BaseRule, RuleKind

    attrs = dict(
        techniques=(),
        kind=kind or RuleKind.DETECTION,
        on_failure=on_failure,
        applies=property(lambda self: True),
        perform=perform,
    )
    return type(name, (BaseRule,), attrs)


async def sleeps_forever(self):
    await asyncio.sleep(30)
    return Message(code="never_seen", text="should not arrive")


async def raises(self):
    raise RuntimeError("dependency exploded")


async def finds_something(self):
    return Message(code="test_finding", text="found", context=dict(score=0.2))


class TestLatencyBudget:
    def test_a_hung_rule_does_not_hold_the_decision(self, application, no_geoip):
        Slow = make_rule("SlowRule", perform=sleeps_forever)
        budget(application, 200)

        started = time.monotonic()
        with with_rules(Slow):
            result = audit(application, transfer_event())
        elapsed = time.monotonic() - started

        assert elapsed < 2.0
        assert [d["rule"] for d in result.degraded] == ["SlowRule"]
        assert result.degraded[0]["reason"] == "timeout"
        assert "rule_unavailable" in result.factors

    def test_the_other_rules_still_contribute(self, application, no_geoip):
        Slow = make_rule("SlowRule", perform=sleeps_forever)
        Finds = make_rule("FindsRule", perform=finds_something)
        budget(application, 200)

        with with_rules(Slow, Finds):
            result = audit(application, transfer_event())

        assert "test_finding" in result.factors

    def test_an_unavailable_rule_is_never_scored(self, application, no_geoip):
        Slow = make_rule("SlowRule", perform=sleeps_forever)
        budget(application, 200)

        with with_rules(Slow):
            result = audit(application, transfer_event())

        assert result.risk_score == 0.0

    def test_a_complete_decision_reports_nothing_degraded(self, application, no_geoip):
        result = audit(application, transfer_event())

        assert result.degraded == []
        assert "rule_unavailable" not in result.factors

    def test_the_budget_comes_from_the_policy(self, application):
        from core.audit.auditor import Auditor

        budget(application, 150)
        application.policy.refresh_from_db()

        assert Auditor.latency_budget(application.policy) == 0.15

    def test_a_nonsense_budget_falls_back_to_the_default(self):
        from core.audit.auditor import Auditor
        from devkit.struct import Struct

        for value in (None, 0, -5, "fast", True):
            policy = Struct(latency_budget_ms=value)
            assert Auditor.latency_budget(policy) == Auditor.DEFAULT_LATENCY_BUDGET_MS / 1000


class TestRuleErrors:
    def test_a_raising_rule_does_not_fail_the_audit(self, application, no_geoip):
        Broken = make_rule("BrokenRule", perform=raises)

        with with_rules(Broken):
            result = audit(application, transfer_event())

        assert result.degraded == [dict(rule="BrokenRule", reason="error", error="RuntimeError")]
        assert "rule_unavailable" in result.factors

    def test_the_failure_is_recorded_on_the_decision(self, application, no_geoip):
        from core.models import AuditLog

        Broken = make_rule("BrokenRule", perform=raises)

        with with_rules(Broken):
            audit(application, transfer_event(client_id="recorded_1"))

        log = AuditLog.objects.filter(actor_id="recorded_1").first()
        assert log.context["degraded"][0]["rule"] == "BrokenRule"


class TestFailMode:
    def test_a_detection_fails_open(self, application, no_geoip):
        """It found nothing, and nothing is what the decision records."""
        Broken = make_rule("BrokenDetection", perform=raises)

        with with_rules(Broken):
            result = audit(application, transfer_event())

        assert result.should_review is False
        assert result.should_block is False

    def test_a_control_fails_closed(self, application, no_geoip):
        """It did not check, so the decision goes to a human."""
        from core.audit.rules.base_rule import RuleKind

        Broken = make_rule("BrokenControl", kind=RuleKind.CONTROL, perform=raises)

        with with_rules(Broken):
            result = audit(application, transfer_event())

        assert result.should_review is True
        assert result.should_block is False
        assert result.risk_score == 0.0
        assert result.recommendation.startswith("REVIEW")

    def test_a_control_that_times_out_fails_closed(self, application, no_geoip):
        from core.audit.rules.base_rule import RuleKind

        Slow = make_rule("SlowControl", kind=RuleKind.CONTROL, perform=sleeps_forever)
        budget(application, 200)

        with with_rules(Slow):
            result = audit(application, transfer_event())

        assert result.should_review is True

    def test_a_rule_can_say_otherwise(self, application, no_geoip):
        from core.audit.rules.base_rule import FailMode

        Broken = make_rule("StrictDetection", on_failure=FailMode.CLOSED, perform=raises)

        with with_rules(Broken):
            result = audit(application, transfer_event())

        assert result.should_review is True

    def test_the_default_is_decided_by_kind(self):
        from core.audit.rules.base_rule import FailMode, RuleKind

        assert make_rule("A", perform=raises).fail_mode() == FailMode.OPEN
        assert make_rule("B", kind=RuleKind.CONTROL, perform=raises).fail_mode() == FailMode.CLOSED
        assert make_rule("C", kind=RuleKind.CORROBORATION, perform=raises).fail_mode() == FailMode.OPEN

    def test_every_shipped_control_fails_closed(self):
        from core.audit.auditor import Auditor
        from core.audit.rules.base_rule import FailMode, RuleKind

        controls = [r for r in Auditor.rule_classes if r.kind == RuleKind.CONTROL]

        assert controls
        assert all(r.fail_mode() == FailMode.CLOSED for r in controls)


class TestHardBlock:
    """A sanctions hit is not weighed; it decides."""

    def sanctioned(self, **context):
        return dict(
            code="sanctioned_address", text="listed",
            context=dict(severity=1.0, hard_block=True, **context),
        )

    def test_a_hard_block_survives_a_clean_history(self):
        from core.scoring import RiskEngine

        engine = RiskEngine()
        weak = dict(code="datacenter_ip", text="", context={})

        # Without the flag, blending with a spotless history lands this under
        # the block line — which is the defect this exists to close.
        unflagged = engine.calculate_risk(
            [dict(code="sanctioned_address", text="", context=dict(severity=1.0)), weak],
            historical_risk_scores=[0.0] * 10,
        )
        assert unflagged.total_score < engine.thresholds.block_at

        result = engine.calculate_risk(
            [self.sanctioned(), weak], historical_risk_scores=[0.0] * 10,
        )

        assert result.should_block is True
        assert result.level.value == "critical"
        assert result.recommendation.startswith("BLOCK")
        assert result.total_score >= engine.thresholds.block_at
        assert result.metadata["hard_blocks"] == ["sanctioned_address"]

    def test_a_hard_block_survives_a_lenient_calibration(self):
        from core.scoring import RiskEngine, RiskThresholds

        engine = RiskEngine(thresholds=RiskThresholds(block_at=0.99, review_at=0.98))
        result = engine.calculate_risk([self.sanctioned()])

        assert result.should_block is True

    def test_shadow_still_suppresses_it(self, application, no_geoip):
        """Shadow means shadow; the hard block is reported, not taken."""
        from tests.unit.test_sanctions import load
        from tests.unit.test_crypto import transfer

        application.enforcement = "shadow"
        application.save(update_fields=["enforcement"])
        load()

        result = transfer(
            application, type="debit", client_id="shadow_sanctioned",
            counterparty_address="0x7F367cC41522cE07553e823bf3be79A889DEbe1B",
        )

        assert result.would_block is True
        assert result.should_block is False


class TestForcedReview:
    def test_unscreened_sanctions_go_to_review_without_touching_the_score(
        self, application, no_geoip,
    ):
        from django.core.cache import cache
        from core.intelligence.sanctions import SanctionsList
        from tests.unit.test_crypto import transfer

        # Another test may have loaded a list into the shared cache.
        cache.clear()
        SanctionsList._addresses = None if hasattr(SanctionsList, "_addresses") else None

        result = transfer(
            application, type="debit", client_id="unscreened_1",
            counterparty_address="0x3B61A6E5D0c2E7A0f5E7F1a2B3c4D5e6F7a8B9c0",
        )

        assert "sanctions_screening_unavailable" in result.factors
        assert result.risk_score == 0.0
        assert result.should_review is True
        assert result.should_block is False
        assert result.recommendation.startswith("REVIEW")


class TestLevelsFollowThresholds:
    def test_the_level_reads_from_the_calibrated_thresholds(self):
        from core.scoring import RiskLevel, RiskThresholds

        strict = RiskThresholds(block_at=0.6, review_at=0.4)

        assert RiskLevel.from_score(0.65) == RiskLevel.HIGH
        assert RiskLevel.from_score(0.65, strict) == RiskLevel.CRITICAL
        assert RiskLevel.from_score(0.45, strict) == RiskLevel.HIGH
        assert RiskLevel.from_score(0.2, strict) == RiskLevel.LOW

    def test_the_default_cut_offs_are_unchanged(self):
        from core.scoring import RiskLevel

        assert RiskLevel.from_score(0.29) == RiskLevel.LOW
        assert RiskLevel.from_score(0.3) == RiskLevel.MEDIUM
        assert RiskLevel.from_score(0.5) == RiskLevel.HIGH
        assert RiskLevel.from_score(0.7) == RiskLevel.CRITICAL

    def test_the_recommendation_follows_the_block_flag(self):
        """Once block_at moves, "BLOCK" and should_block must still agree."""
        from core.scoring import RiskEngine, RiskThresholds

        engine = RiskEngine(thresholds=RiskThresholds(block_at=0.5, review_at=0.3))
        result = engine.calculate_risk([
            dict(code="velocity_exceeded_per_hour", text="", context={}),
        ])

        assert result.should_block is True
        assert result.recommendation.startswith("BLOCK")

    def test_the_challenge_threshold_is_part_of_the_policy(self):
        from core.services.simulate_policy import SimulatePolicy

        thresholds = SimulatePolicy.merge_thresholds(dict(challenge_at=0.3))

        assert thresholds.challenge_at == 0.3
        assert SimulatePolicy.describe_thresholds(thresholds)["challenge_at"] == 0.3


class TestLockCache:
    def test_different_arguments_are_cached_separately(self):
        from core.audit.lock_cache import LockCache, lockcache

        calls = []

        class Lookup(LockCache):
            @lockcache(lambda key: key)
            async def fetch(self, key):
                calls.append(key)
                return key.upper()

        async def run():
            lookup = Lookup()
            first = await lookup.fetch("a")
            second = await lookup.fetch("b")
            again = await lookup.fetch("a")
            return first, second, again

        assert asyncio.run(run()) == ("A", "B", "A")
        assert calls == ["a", "b"]

    def test_methods_do_not_share_a_namespace(self):
        from core.audit.lock_cache import LockCache, lockcache

        class Lookup(LockCache):
            @lockcache(lambda key: key)
            async def one(self, key):
                return f"one:{key}"

            @lockcache(lambda key: key)
            async def two(self, key):
                return f"two:{key}"

        async def run():
            lookup = Lookup()
            return await lookup.one("x"), await lookup.two("x")

        assert asyncio.run(run()) == ("one:x", "two:x")
