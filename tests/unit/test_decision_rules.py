"""
Decisions a person wrote down hold regardless of the arithmetic.

block > review > challenge > allow. A block ignores a clean history and a
lenient calibration. An allow waives only what the score asked for; it never
overrides a block, and it never silences a control that did not run. The
organization's rules apply to every application under it and cannot be
removed by one; its thresholds are a ceiling an application may tighten but
not loosen.
"""

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from django.utils import timezone

from core.decision import DecisionRules, validate_rules


def audit(application, event):
    from core.audit.auditor import Auditor

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=None),
    ):
        return asyncio.run(Auditor.audit(event, application.policy, send_alerts=False))


def transfer(application, *, client_id="user_1", ip_address="102.91.133.202", **extra):
    from core.audit.events import TransactionEvent

    return audit(application, TransactionEvent(
        id=f"tx_{client_id}_{timezone.now().timestamp()}", type="debit", amount=10,
        currency_code="USD", client_id=client_id, ip_address=ip_address,
        user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0", **extra,
    ))


def signup(application, *, email, client_id=None, ip_address="102.91.133.202", country="US"):
    from core.audit.events import RegistrationEvent

    client_id = client_id or email
    return audit(application, RegistrationEvent(
        id=client_id, client_id=client_id, email=email, country=country,
        ip_address=ip_address, user_agent="Mozilla/5.0 Chrome/120.0", action="registration",
    ))


def set_rules(policy, **rules):
    policy.rules = rules
    policy.save(update_fields=["rules"])
    policy.refresh_from_db()


def org_policy(application, **fields):
    from core.models import OrganizationPolicy

    return OrganizationPolicy.objects.create(organization=application.organization, **fields)


def rule(subject, pattern, **extra):
    return dict(subject=subject, pattern=pattern, **extra)


class TestMatchers:
    def matches(self, subject, pattern, **facts):
        rules = DecisionRules(("application", dict(block=[rule(subject, pattern)])))
        return bool(rules.matches(facts)["block"])

    def test_ip_and_cidr(self):
        assert self.matches("ip", "203.0.113.9", ip="203.0.113.9")
        assert not self.matches("ip", "203.0.113.9", ip="203.0.113.10")
        assert self.matches("cidr", "41.58.100.0/24", ip="41.58.100.77")
        assert not self.matches("cidr", "41.58.100.0/24", ip="41.58.101.1")
        assert self.matches("cidr", "2001:db8::/32", ip="2001:db8::1")

    def test_country_and_asn(self):
        assert self.matches("country", "ng", country="NG")
        assert not self.matches("country", "NG", country="GH")
        assert self.matches("asn", "AS14061", asn=14061)
        assert self.matches("asn", "14061", asn="AS14061")

    def test_email_root_collapses_tags_and_dots(self):
        assert self.matches("email_root", "pen.test+1@gmail.com", email_root="pentest@gmail.com")
        assert not self.matches("email_root", "other@gmail.com", email_root="pentest@gmail.com")

    def test_email_domain_and_wildcard(self):
        assert self.matches("email_domain", "wearehackerone.com", email_domain="wearehackerone.com")
        assert not self.matches("email_domain", "hackerone.com", email_domain="wearehackerone.com")
        assert self.matches("email_domain", "*.example.com", email_domain="mail.example.com")
        assert self.matches("email_domain", "*.example.com", email_domain="example.com")
        assert not self.matches("email_domain", "*.example.com", email_domain="notexample.com")

    def test_client_id_glob(self):
        assert self.matches("client_id", "partner-*", client_id="partner-42")
        assert not self.matches("client_id", "partner-*", client_id="user-42")
        assert self.matches("client_id", "user_1", client_id="user_1")

    def test_device(self):
        assert self.matches("device", "fp_abc", devices=["ignored", "fp_abc"])
        assert not self.matches("device", "fp_abc", devices=[None])

    def test_wallet_and_counterparty_are_normalised(self):
        evm = "0x7F367cC41522cE07553e823bf3be79A889DEbe1B"
        from core.intelligence.wallet_intelligence import address_key

        assert self.matches("wallet", evm.lower(), wallet=address_key(evm, "polygon"), chain="polygon")
        assert self.matches("counterparty", evm, counterparties=[address_key(evm.lower(), "base")], chain="base")
        assert self.matches("counterparty", "merchant_77", counterparties=["merchant_77"])

    def test_factor_code_and_glob(self):
        assert self.matches("factor", "campaign_motif", factors=["machine_session", "campaign_motif"])
        assert self.matches("factor", "velocity_exceeded_*", factors=["velocity_exceeded_per_hour"])
        assert not self.matches("factor", "campaign_motif", factors=[])

    def test_a_fact_that_is_missing_never_matches(self):
        assert not self.matches("ip", "8.8.8.8")
        assert not self.matches("country", "US")
        assert not self.matches("email_root", "a@b.com")

    def test_an_expired_rule_is_ignored(self):
        past = (timezone.now() - timedelta(hours=1)).isoformat()
        future = (timezone.now() + timedelta(hours=1)).isoformat()
        expired = DecisionRules(("application", dict(block=[rule("ip", "8.8.8.8", expires_at=past)])))
        live = DecisionRules(("application", dict(block=[rule("ip", "8.8.8.8", expires_at=future)])))

        assert not expired.matches(dict(ip="8.8.8.8"))["block"]
        assert live.matches(dict(ip="8.8.8.8"))["block"]

    def test_layers_are_both_read_and_named(self):
        rules = DecisionRules(
            ("organization", dict(block=[rule("cidr", "10.0.0.0/8")])),
            ("application", dict(review=[rule("ip", "10.1.1.1")])),
        )
        found = rules.matches(dict(ip="10.1.1.1"))

        assert found["block"][0]["layer"] == "organization"
        assert found["review"][0]["layer"] == "application"


class TestValidation:
    def test_a_good_payload_has_no_errors(self):
        assert validate_rules(dict(
            block=[rule("cidr", "10.0.0.0/8", reason="internal"), rule("asn", "AS14061")],
            allow=[rule("client_id", "partner-*")],
        )) == []

    def test_bad_patterns_are_named_by_path(self):
        errors = validate_rules(dict(
            block=[rule("cidr", "not-a-range"), rule("country", "Nigeria")],
            review=[rule("nonsense", "x")],
            weird=[],
        ))
        paths = {error.path for error in errors}

        assert "rules.block[0].pattern" in paths
        assert "rules.block[1].pattern" in paths
        assert "rules.review[0].subject" in paths
        assert "rules" in paths

    def test_shape_errors(self):
        assert validate_rules("block everything")[0].code == "dict"
        assert validate_rules(dict(block="8.8.8.8"))[0].path == "rules.block"
        assert validate_rules(dict(block=[rule("ip", "8.8.8.8", expires_at="tomorrow")]))[0].path.endswith("expires_at")


class TestBlock:
    def test_a_blocked_range_is_a_hard_block(self, application, no_geoip):
        set_rules(application.policy, block=[rule("cidr", "41.58.100.0/24", reason="known actor")])

        result = transfer(application, ip_address="41.58.100.5")

        assert result.should_block is True
        assert "policy_block" in result.factors
        assert result.recommendation.startswith("BLOCK")
        assert result.policy_matches["block"][0]["reason"] == "known actor"

    def test_it_survives_a_lenient_calibration(self, application, no_geoip):
        policy = application.policy
        policy.calibration = dict(thresholds=dict(block_at=0.99, review_at=0.98))
        policy.save(update_fields=["calibration"])
        set_rules(policy, block=[rule("ip", "41.58.100.5")])

        assert transfer(application, ip_address="41.58.100.5").should_block is True

    def test_an_unlisted_address_is_untouched(self, application, no_geoip):
        set_rules(application.policy, block=[rule("cidr", "41.58.100.0/24")])

        result = transfer(application, ip_address="102.91.133.202")

        assert result.should_block is False
        assert "policy_block" not in result.factors

    def test_shadow_still_suppresses_it(self, application, no_geoip):
        application.enforcement = "shadow"
        application.save(update_fields=["enforcement"])
        set_rules(application.policy, block=[rule("ip", "41.58.100.5")])

        result = transfer(application, ip_address="41.58.100.5")

        assert result.would_block is True
        assert result.should_block is False

    def test_a_block_on_a_rule_code(self, application, no_geoip):
        """Rules on what the rules found: block whatever the bot detector flags."""
        set_rules(application.policy, block=[rule("factor", "bot_detected:*")])

        from core.audit.events import TransactionEvent
        result = audit(application, TransactionEvent(
            id="tx_bot", type="debit", amount=10, currency_code="USD",
            client_id="bot_1", ip_address="102.91.133.202", user_agent="curl/8.5.0",
        ))

        assert any(code.startswith("bot_detected") for code in result.factors)
        assert result.should_block is True

    def test_an_email_domain_block_at_signup(self, application, no_geoip):
        set_rules(application.policy, block=[rule("email_domain", "*.wearehackerone.com")])

        assert signup(application, email="pentest.figo+3@wearehackerone.com").should_block is True
        assert signup(application, email="someone@gmail.com").should_block is False


class TestReviewAndChallenge:
    def test_review_forces_a_case_without_touching_the_score(self, application, no_geoip):
        from core.models import Case

        set_rules(application.policy, review=[rule("country", "KP")])

        result = signup(application, email="someone@gmail.com", country="KP")

        assert result.should_review is True
        assert result.should_block is False
        assert result.risk_score == 0.0
        assert Case.objects.filter(application=application).exists()

    def test_challenge_forces_a_step_up(self, application, no_geoip):
        set_rules(application.policy, challenge=[rule("asn", "14061")])

        rules = DecisionRules(("application", application.policy.rules))
        assert rules.matches(dict(asn=14061))["challenge"]

        set_rules(application.policy, challenge=[rule("cidr", "41.73.20.0/24")])
        result = transfer(application, ip_address="41.73.20.9")

        assert result.should_challenge is True
        assert result.should_block is False
        assert result.recommendation.startswith("CHALLENGE")

    def test_block_beats_challenge(self, application, no_geoip):
        set_rules(
            application.policy,
            block=[rule("ip", "41.73.20.9")],
            challenge=[rule("cidr", "41.73.20.0/24")],
        )
        result = transfer(application, ip_address="41.73.20.9")

        assert result.should_block is True
        assert result.should_challenge is False


class TestAllow:
    def bot_transfer(self, application, client_id="partner-7"):
        from core.audit.events import TransactionEvent
        return audit(application, TransactionEvent(
            id=f"tx_{client_id}", type="debit", amount=10, currency_code="USD",
            client_id=client_id, ip_address="45.155.205.77", user_agent="curl/8.0",
        ))

    def test_waives_review_and_challenge_the_score_asked_for(self, application, no_geoip):
        from core.models import Case

        before = self.bot_transfer(application, "stranger")
        assert before.should_review or before.should_challenge

        set_rules(application.policy, allow=[rule("client_id", "partner-*")])
        result = self.bot_transfer(application)

        assert "policy_allow" in result.factors
        assert result.should_review is False
        assert result.should_challenge is False
        assert not Case.objects.filter(audit_log_id=result.audit_id).exists()

    def test_never_overrides_a_block(self, application, no_geoip):
        set_rules(
            application.policy,
            block=[rule("ip", "41.73.20.9")],
            allow=[rule("client_id", "partner-*")],
        )
        result = transfer(application, client_id="partner-1", ip_address="41.73.20.9")

        assert result.should_block is True

    def test_never_silences_a_control_that_did_not_run(self, application, no_geoip):
        from django.core.cache import cache
        from core.intelligence.sanctions import SanctionsList

        cache.clear()
        SanctionsList._version = None
        SanctionsList._addresses = frozenset()
        set_rules(application.policy, allow=[rule("client_id", "partner-*")])

        result = transfer(
            application, client_id="partner-9", chain="polygon", asset="USDC",
            counterparty_address="0x3B61A6E5D0c2E7A0f5E7F1a2B3c4D5e6F7a8B9c0",
        )

        assert "sanctions_screening_unavailable" in result.factors
        assert result.should_review is True


class TestOrganizationLayer:
    def test_org_rules_apply_to_every_application(self, application, no_geoip):
        org_policy(application, rules=dict(block=[rule("cidr", "41.58.100.0/24")]))

        result = transfer(application, ip_address="41.58.100.5")

        assert result.should_block is True
        assert result.policy_matches["block"][0]["layer"] == "organization"

    def test_an_application_cannot_remove_them(self, application, no_geoip):
        org_policy(application, rules=dict(block=[rule("cidr", "41.58.100.0/24")]))
        set_rules(application.policy, allow=[rule("cidr", "41.58.100.0/24")])

        assert transfer(application, ip_address="41.58.100.5").should_block is True

    def test_the_ceiling_caps_the_thresholds(self, application, no_geoip):
        from core.calibration import engine_for
        from core.models import OrganizationPolicy

        policy = application.policy
        policy.calibration = dict(thresholds=dict(block_at=0.9, review_at=0.8))
        policy.save(update_fields=["calibration"])
        org = org_policy(application, max_block_at=0.6, max_review_at=0.4)

        engine = engine_for(policy, org)
        assert engine.thresholds.block_at == 0.6
        assert engine.thresholds.review_at == 0.4

    def test_an_application_may_be_stricter_than_the_ceiling(self, application):
        from core.calibration import engine_for

        policy = application.policy
        policy.calibration = dict(thresholds=dict(block_at=0.5, review_at=0.3))
        policy.save(update_fields=["calibration"])
        org = org_policy(application, max_block_at=0.8)

        assert engine_for(policy, org).thresholds.block_at == 0.5

    def test_required_enforcement_overrides_shadow(self, application, no_geoip):
        application.enforcement = "shadow"
        application.save(update_fields=["enforcement"])
        org_policy(application, required_enforcement="enforcing", rules=dict(block=[rule("ip", "41.58.100.5")]))

        result = transfer(application, ip_address="41.58.100.5")

        assert result.would_block is True
        assert result.should_block is True

    def test_without_an_org_policy_nothing_changes(self, application, no_geoip):
        from core.calibration import engine_for

        assert engine_for(application.policy, None).thresholds.block_at == 0.7


class TestDisabledRules:
    def test_a_disabled_rule_sits_out_and_is_recorded(self, application, no_geoip):
        from core.models import AuditLog

        policy = application.policy
        policy.disabled_rules = ["BotSignalRule"]
        policy.save(update_fields=["disabled_rules"])

        from core.audit.events import TransactionEvent
        result = audit(application, TransactionEvent(
            id="tx_dis", type="debit", amount=10, currency_code="USD",
            client_id="dis_1", ip_address="102.91.133.202", user_agent="curl/8.5.0",
        ))

        assert "BotSignalRule" not in result.rules
        assert not any(code.startswith("bot_detected") for code in result.factors)
        assert result.disabled_rules == ["BotSignalRule"]
        assert AuditLog.objects.get(id=result.audit_id).context["disabled_rules"] == ["BotSignalRule"]

    def test_the_organization_can_disable_across_the_estate(self, application, no_geoip):
        org_policy(application, disabled_rules=["BotSignalRule"])

        result = transfer(application)

        assert "BotSignalRule" not in result.rules
