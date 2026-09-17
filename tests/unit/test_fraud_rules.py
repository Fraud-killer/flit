"""
Unit Tests for FLIT Fraud Detection Rules

Runs the payment fraud rules through BaseRule.execute with realistic
payloads based on patterns observed in real transaction data.
"""

import asyncio
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def clear_cache():
    from django.core.cache import cache
    cache.clear()
    yield
    cache.clear()


def make_policy():
    return SimpleNamespace(
        application=SimpleNamespace(id="app_1"),
        aml_cft_limit="USD 10,000.00",
        kyc_level_limits={},
    )


def make_event(**attributes):
    from core.audit.events import TransactionEvent

    attributes.setdefault("id", "tx_1")
    attributes.setdefault("type", "debit")
    return TransactionEvent(**attributes)


def run_rule(rule_class, event, policy=None):
    from core.audit.scope import Scope

    rule = rule_class(event=event, policy=policy or make_policy(), scope=Scope())
    if not rule.applies:
        return []
    return asyncio.run(rule.execute(False))


def codes(messages):
    return [message.code for message in messages]


FARADAY_TRANSACTION = dict(
    amount=10,
    currency_code="USD",
    status="failed",
    card_fingerprint="card_faraday",
    gateway_message="Declined by Issuer",
    browser_details={
        "user_agent": "Faraday v1.10.4",
        "javascript_enabled": False,
        "screen_width": 480,
        "screen_height": 640,
    },
    request_details={"ipAddress": "54.217.46.204"},
    billing={
        "city": "Pleasantville",
        "address1": "Second Street 23",
        "address2": "Second Street 23",
        "zip_code": "90210",
        "country": "TR",
    },
)


class TestRuleRegistration:
    def test_all_registered_rules_instantiate(self):
        from core.audit.auditor import Auditor
        from core.audit.scope import Scope

        for rule_class in Auditor.rule_classes:
            rule = rule_class(event=make_event(), policy=make_policy(), scope=Scope())
            assert isinstance(rule.applies, bool), rule_class.__name__

    def test_payment_rules_skip_events_without_payment_fields(self):
        from core.audit import rules

        for rule_class in (
            rules.PaymentFraudRule,
            rules.GatewayPatternRule,
            rules.CardTestingRule,
            rules.IPConcentrationRule,
            rules.ThreeDSTimeoutRule,
            rules.FakeAddressRule,
            rules.RetryAttackRule,
            rules.IssuerSignalRule,
        ):
            assert run_rule(rule_class, make_event(amount=10)) == [], rule_class.__name__

    def test_payment_rules_do_not_apply_to_client_events(self):
        from core.audit import rules
        from core.audit.events import ClientEvent
        from core.audit.scope import Scope

        event = ClientEvent(id="client_1", gateway_message="Suspected Fraud")
        rule = rules.IssuerSignalRule(event=event, policy=make_policy(), scope=Scope())
        assert not rule.applies

    def test_payload_reads_ip_from_request_details(self):
        from core.audit.rules.payment_rule import PaymentRule

        class Probe(PaymentRule):
            pass

        from core.audit.scope import Scope

        event = make_event(client_id="cust_1", request_details={"ipAddress": "1.2.3.4"})
        payload = Probe(event=event, policy=make_policy(), scope=Scope()).payload
        assert payload["ip_address"] == "1.2.3.4"
        assert payload["customer_id"] == "cust_1"
        assert "visit_id" not in payload


class TestPaymentFraudRule:
    def test_detects_faraday_client(self):
        from core.audit.rules import PaymentFraudRule

        messages = run_rule(PaymentFraudRule, make_event(**FARADAY_TRANSACTION))
        assert "automated_client" in codes(messages)
        assert "javascript_disabled" in codes(messages)
        assert all(m.context["rule"] == "PaymentFraudRule" for m in messages)
        assert all(0 < m.context["score"] <= 1 for m in messages)

    def test_detects_curl_client(self):
        from core.audit.rules import PaymentFraudRule

        event = make_event(browser_details={"user_agent": "curl/7.68.0", "language": "en"})
        assert "automated_client" in codes(run_rule(PaymentFraudRule, event))

    def test_allows_normal_browser(self):
        from core.audit.rules import PaymentFraudRule

        event = make_event(
            card_fingerprint="card_ok",
            browser_details={
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "javascript_enabled": True,
                "screen_width": 1920,
                "screen_height": 1080,
                "language": "en-US",
            },
        )
        assert run_rule(PaymentFraudRule, event) == []

    def test_no_browser_details_is_not_missing_user_agent(self):
        from core.audit.rules import PaymentFraudRule

        event = make_event(card_fingerprint="card_ok")
        assert "missing_user_agent" not in codes(run_rule(PaymentFraudRule, event))


class TestFakeAddressRule:
    def test_detects_pleasantville_pattern(self):
        from core.audit.rules import FakeAddressRule

        found = codes(run_rule(FakeAddressRule, make_event(**FARADAY_TRANSACTION)))
        for code in (
            "fake_city",
            "fake_street",
            "fake_zip_code",
            "duplicate_address_lines",
            "impossible_address_geography",
        ):
            assert code in found

    def test_allows_real_address(self):
        from core.audit.rules import FakeAddressRule

        event = make_event(billing={
            "city": "Istanbul",
            "address1": "Atatürk Caddesi No: 45",
            "address2": "Daire 3",
            "zip_code": "34000",
            "country": "TR",
        })
        assert run_rule(FakeAddressRule, event) == []


class TestThreeDSTimeoutRule:
    @pytest.mark.parametrize("message", [
        "3DS Timeout",
        "3ds_timeout",
        "Cancelled by Timeout",
        "Authentication Timeout",
    ])
    def test_detects_3ds_timeout_message(self, message):
        from core.audit.rules import ThreeDSTimeoutRule

        event = make_event(gateway_message=message)
        assert codes(run_rule(ThreeDSTimeoutRule, event)) == ["three_ds_timeout"]

    def test_allows_successful_3ds(self):
        from core.audit.rules import ThreeDSTimeoutRule

        assert run_rule(ThreeDSTimeoutRule, make_event(gateway_message="Payment")) == []


class TestGatewayPatternRule:
    def test_categorizes_fraud_decline(self):
        from core.audit.rules import GatewayPatternRule

        event = make_event(status="failed", gateway_message="Declined by Acquirer: Anti-fraud")
        messages = run_rule(GatewayPatternRule, event)
        assert codes(messages) == ["gateway_issuer_fraud"]
        assert messages[0].context["score"] == 0.9

    def test_insufficient_funds_is_low_risk(self):
        from core.audit.rules import GatewayPatternRule

        event = make_event(status="failed", gateway_message="Insufficient Funds")
        messages = run_rule(GatewayPatternRule, event)
        assert codes(messages) == ["gateway_nsf"]
        assert messages[0].context["score"] == 0.1

    def test_ignores_successful_transactions(self):
        from core.audit.rules import GatewayPatternRule

        event = make_event(status="success", gateway_message="Suspected Fraud")
        assert run_rule(GatewayPatternRule, event) == []

    def test_escalates_repeated_fraud_declines(self):
        from core.audit.rules import GatewayPatternRule

        def decline():
            return make_event(
                status="failed",
                card_fingerprint="card_1",
                gateway_message="Suspected Fraud",
            )

        assert codes(run_rule(GatewayPatternRule, decline())) == ["gateway_fraud_flag"]
        assert codes(run_rule(GatewayPatternRule, decline())) == ["gateway_repeated_fraud_declines"]


class TestCardTestingRule:
    def test_detects_high_failure_rate(self):
        from core.audit.rules import CardTestingRule

        def attempt():
            return make_event(amount=50, status="failed", card_fingerprint="card_1")

        assert run_rule(CardTestingRule, attempt()) == []
        assert "card_testing_high_failure_rate" in codes(run_rule(CardTestingRule, attempt()))

    def test_detects_multiple_small_transactions_from_ip(self):
        from core.audit.rules import CardTestingRule

        results = [
            codes(run_rule(CardTestingRule, make_event(
                amount=1,
                status="success",
                ip_address="203.0.113.7",
                card_fingerprint=f"card_{n}",
            )))
            for n in range(3)
        ]
        assert "card_testing_multiple_small_transactions" not in results[1]
        assert "card_testing_multiple_small_transactions" in results[2]

    def test_amount_is_in_major_units(self):
        from core.audit.rules import CardTestingRule

        for n in range(5):
            messages = run_rule(CardTestingRule, make_event(
                amount=400,
                status="success",
                ip_address="203.0.113.7",
                card_fingerprint=f"card_{n}",
            ))
            assert "card_testing_multiple_small_transactions" not in codes(messages)


class TestIPConcentrationRule:
    def test_detects_many_customers_on_one_ip(self):
        from core.audit.rules import IPConcentrationRule

        results = [
            codes(run_rule(IPConcentrationRule, make_event(
                ip_address="203.0.113.9",
                client_id=f"customer_{n}",
            )))
            for n in range(6)
        ]
        assert "multiple_customers_per_ip" not in results[4]
        assert "multiple_customers_per_ip" in results[5]

    def test_no_longer_flags_datacenter_itself(self):
        from core.audit.rules import IPConcentrationRule

        event = make_event(ip_address="54.217.46.204")
        assert "datacenter_ip" not in codes(run_rule(IPConcentrationRule, event))


class TestRetryAttackRule:
    def test_detects_rapid_retries(self):
        from core.audit.rules import RetryAttackRule

        results = [
            codes(run_rule(RetryAttackRule, make_event(
                payment_instrument={"card": {"number": "411111******1111"}},
            )))
            for _ in range(4)
        ]
        assert results[2] == []
        assert "card_retry_per_minute" in results[3]

    def test_detects_customer_card_cycling(self):
        from core.audit.rules import RetryAttackRule

        results = [
            codes(run_rule(RetryAttackRule, make_event(
                client_id="customer_1",
                payment_instrument={"card": {"number": f"411111******{n:04d}"}},
            )))
            for n in range(5)
        ]
        assert "customer_card_cycling" not in results[3]
        assert "customer_card_cycling" in results[4]


class TestIssuerSignalRule:
    def test_categorizes_fraud_signals(self):
        from core.audit.rules import IssuerSignalRule

        for message in ("Suspected Fraud", "Stolen Card", "Lost Card", "Declined by Acquirer: Anti-fraud"):
            found = codes(run_rule(IssuerSignalRule, make_event(gateway_message=message)))
            assert found == ["issuer_fraud_signal"], message

    def test_categorizes_business_rules(self):
        from core.audit.rules import IssuerSignalRule

        event = make_event(gateway_message="Declined by Issuer: Business Rules")
        assert codes(run_rule(IssuerSignalRule, event)) == ["issuer_velocity_signal"]

    def test_detects_repeated_fraud_flags_on_card(self):
        from core.audit.rules import IssuerSignalRule

        def decline():
            return make_event(
                gateway_message="Suspected Fraud",
                payment_instrument={"card": {"number": "411111******1111"}},
            )

        assert "issuer_repeated_fraud_flags" not in codes(run_rule(IssuerSignalRule, decline()))
        assert "issuer_repeated_fraud_flags" in codes(run_rule(IssuerSignalRule, decline()))


class TestRuleScoring:
    def test_unknown_codes_use_the_rule_score(self):
        from core.scoring import RiskEngine

        result = RiskEngine().calculate_risk([
            {"code": "gateway_nsf", "text": "", "context": {"score": 0.1}},
        ])
        assert result.factors[0].weight == 0.1

    def test_configured_weights_take_precedence(self):
        from core.scoring import RiskEngine

        result = RiskEngine().calculate_risk([
            {"code": "tor_exit_node", "text": "", "context": {"score": 0.1}},
        ])
        assert result.factors[0].weight == 0.8
