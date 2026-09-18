"""
Tests for money-mule detection: pass-through funds, structuring, dormant
accounts waking up, device account farming, known mule networks, and the
account profile a fraud team looks at.

Each pattern is checked twice: that it fires on the mule shape, and that an
ordinary customer doing the same kind of thing does not trip it.
"""

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from django.utils import timezone


def make_visit(visitor_id="visitor_1"):
    from devkit.struct import Struct

    return Struct(
        raw_data={}, fingerprint=visitor_id, city="Lagos", state="Lagos",
        country="Nigeria", latitude=6.5, longitude=3.3, ip="81.2.69.160",
        user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0",
        asn="AS4766", asn_org="Example Telecom", is_datacenter=False,
        vpn=False, proxy=False, tor=False, ip_blocklisted=False,
        incognito=False, bot="notDetected", device_signals={}, suspect_score=0,
    )


def audit(application, visit=None, **attributes):
    from core.audit.auditor import Auditor
    from core.audit.events import TransactionEvent

    attributes.setdefault("id", f"tx_{timezone.now().timestamp()}")
    attributes.setdefault("type", "debit")
    attributes.setdefault("amount", 100)
    attributes.setdefault("currency_code", "NGN")
    attributes.setdefault("client_id", "user_1")

    event = TransactionEvent(**attributes)

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=visit),
    ):
        return asyncio.run(Auditor.audit(event, application.policy, send_alerts=False))


def age_decisions(client_id, days=None, minutes=None, only_credits=False):
    """Move an account's recorded history into the past."""
    from core.models import AuditLog

    queryset = AuditLog.objects.filter(actor_id=client_id)

    if only_credits:
        queryset = queryset.filter(action="transaction_credit")

    for log in queryset:
        log.timestamp = log.timestamp - timedelta(days=days or 0, minutes=minutes or 0)
        log.save(update_fields=["timestamp"])


def factors(result):
    return result.factors


def confirm_fraud(application, result):
    """Label a decision the way a reviewer would: through its case."""
    from core.models import Case, AuditLog

    case = Case.objects.filter(audit_log_id=result.audit_id).first()

    if case:
        return case.resolve(status="confirmed_fraud")

    # Low-risk decisions open no case, so label the decision directly.
    AuditLog.objects.filter(id=result.audit_id).update(label="fraud")
    return None


class TestPassThroughRule:
    def test_flags_money_that_leaves_as_fast_as_it_arrived(self, application, no_geoip):
        audit(application, type="credit", amount=500, counterparty_id="payer_1")

        result = audit(application, type="debit", amount=480, counterparty_id="payee_1")

        assert "pass_through_funds" in factors(result)
        message = next(m for m in result.reasons if m.code == "pass_through_funds")
        assert message.context["ratio"] == 0.96
        assert message.context["credits"] == 1

    def test_ignores_a_customer_spending_part_of_a_balance(self, application, no_geoip):
        audit(application, type="credit", amount=500, counterparty_id="salary")

        result = audit(application, type="debit", amount=60)

        assert "pass_through_funds" not in factors(result)

    def test_ignores_a_payout_long_after_the_money_arrived(self, application, no_geoip):
        audit(application, type="credit", amount=500)
        age_decisions("user_1", days=3)

        result = audit(application, type="debit", amount=490)

        assert "pass_through_funds" not in factors(result)

    def test_threshold_comes_from_the_policy(self, application, no_geoip):
        application.policy.mule_thresholds = {"pass_through_ratio": 0.1}
        application.policy.save()
        application.refresh_from_db()

        audit(application, type="credit", amount=500)
        result = audit(application, type="debit", amount=60)

        assert "pass_through_funds" in factors(result)


class TestStructuringRule:
    def test_flags_many_different_senders(self, application, no_geoip):
        for index in range(6):
            audit(application, type="credit", amount=50, counterparty_id=f"payer_{index}")

        result = audit(application, type="credit", amount=50, counterparty_id="payer_6")

        assert "many_unique_payers" in factors(result)
        message = next(m for m in result.reasons if m.code == "many_unique_payers")
        assert message.context["payers"] == 6

    def test_flags_a_burst_of_credits_without_counterparties(self, application, no_geoip):
        for index in range(9):
            audit(application, type="credit", amount=50)

        result = audit(application, type="credit", amount=50)

        assert "credit_structuring" in factors(result)

    def test_ignores_an_ordinary_pair_of_credits(self, application, no_geoip):
        audit(application, type="credit", amount=500, counterparty_id="salary")

        result = audit(application, type="credit", amount=20, counterparty_id="refund")

        assert "many_unique_payers" not in factors(result)
        assert "credit_structuring" not in factors(result)


class TestDormantAwakeningRule:
    def test_flags_an_account_that_woke_up(self, application, no_geoip):
        audit(application, type="credit", amount=100)
        age_decisions("user_1", days=120)

        result = audit(application, type="debit", amount=900)

        assert "dormant_account_activity" in factors(result)
        message = next(m for m in result.reasons if m.code == "dormant_account_activity")
        assert message.context["dormant_days"] >= 119
        assert message.context["unusual_amount"] is True

    def test_scores_a_familiar_amount_lower(self, application, no_geoip):
        audit(application, type="credit", amount=100)
        age_decisions("user_1", days=120)

        result = audit(application, type="debit", amount=100)

        message = next(m for m in result.reasons if m.code == "dormant_account_activity")
        assert message.context["unusual_amount"] is False
        assert message.context["score"] == 0.5

    def test_ignores_an_account_in_regular_use(self, application, no_geoip):
        audit(application, type="credit", amount=100)

        result = audit(application, type="debit", amount=900)

        assert "dormant_account_activity" not in factors(result)

    def test_ignores_an_account_with_no_history(self, application, no_geoip):
        result = audit(application, type="debit", amount=900)

        assert "dormant_account_activity" not in factors(result)


class TestAccountFarmingRule:
    def test_flags_accounts_created_in_bulk_on_one_device(self, application, no_geoip):
        visit = make_visit()
        result = None

        for index in range(5):
            result = audit(application, visit=visit, client_id=f"farmed_{index}", visit_id="v1")

        assert "account_farming" in factors(result)
        message = next(m for m in result.reasons if m.code == "account_farming")
        assert message.context["new_accounts"] == 5

    def test_ignores_a_device_whose_accounts_are_not_new(self, application, no_geoip):
        from core.models import DeviceAccountLink

        visit = make_visit()

        for index in range(5):
            audit(application, visit=visit, client_id=f"household_{index}", visit_id="v1")

        # A shared family device: the accounts have been around for months.
        DeviceAccountLink.objects.update(first_seen_at=timezone.now() - timedelta(days=90))

        result = audit(application, visit=visit, client_id="household_1", visit_id="v1")

        assert "account_farming" not in factors(result)
        # Still flagged as shared by many accounts, which is the milder signal.
        assert "multi_accounting" in factors(result)


class TestMuleNetworkRule:
    def test_flags_an_account_sharing_a_device_with_confirmed_fraud(self, application, no_geoip):
        visit = make_visit()

        caught = audit(application, visit=visit, client_id="mule_1", visit_id="v1")
        confirm_fraud(application, caught)

        result = audit(application, visit=visit, client_id="mule_2", visit_id="v1")

        assert "mule_network_device" in factors(result)
        message = next(m for m in result.reasons if m.code == "mule_network_device")
        assert message.context["accounts"] == 1

    def test_ignores_a_device_with_no_confirmed_fraud(self, application, no_geoip):
        visit = make_visit()

        audit(application, visit=visit, client_id="user_a", visit_id="v1")
        result = audit(application, visit=visit, client_id="user_b", visit_id="v1")

        assert "mule_network_device" not in factors(result)

    def test_does_not_flag_an_account_for_its_own_label(self, application, no_geoip):
        visit = make_visit()

        caught = audit(application, visit=visit, client_id="mule_1", visit_id="v1")
        confirm_fraud(application, caught)

        result = audit(application, visit=visit, client_id="mule_1", visit_id="v1")

        assert "mule_network_device" not in factors(result)


class TestMuleRiskCombines:
    def test_a_full_mule_pattern_scores_high(self, application, no_geoip):
        visit = make_visit()

        for index in range(6):
            audit(application, visit=visit, type="credit", amount=50,
                  client_id="mule", counterparty_id=f"victim_{index}", visit_id="v1")

        result = audit(application, visit=visit, type="debit", amount=290,
                       client_id="mule", counterparty_id="herder", visit_id="v1")

        assert "pass_through_funds" in factors(result)
        assert "many_unique_payers" in factors(result)
        assert result.risk_level in ("high", "critical")
        assert result.should_review


class TestAccountProfile:
    def client_for(self, application):
        from rest_framework.test import APIClient
        from core.auth.actor import Actor

        client = APIClient()
        client.force_authenticate(user=None, token=Actor(application))
        return client

    def test_profile_shows_flow_devices_and_signals(self, application, no_geoip):
        visit = make_visit()

        for index in range(6):
            audit(application, visit=visit, type="credit", amount=50,
                  client_id="mule", counterparty_id=f"victim_{index}", visit_id="v1")

        audit(application, visit=visit, type="debit", amount=290,
              client_id="mule", counterparty_id="herder", visit_id="v1")

        response = self.client_for(application).get(
            f"/api/v1/applications/{application.id}/accounts/mule"
        )

        assert response.status_code == 200, response.data
        account = response.data["data"]["account"]

        assert account["client_id"] == "mule"
        assert account["flow_30d"]["credits"] == 6
        assert account["flow_30d"]["debits"] == 1
        assert account["flow_30d"]["unique_payers"] == 6
        assert account["flow_30d"]["pass_through_ratio"] == round(290 / 300, 4)
        assert account["mule_signals"]["many_unique_payers"] >= 1
        assert account["mule_signals"]["pass_through_funds"] == 1
        assert len(account["devices"]) == 1
        assert account["devices"][0]["shared_with_accounts"] == 0
        assert account["open_cases"] >= 1

    def test_unknown_account_is_rejected(self, application):
        response = self.client_for(application).get(
            f"/api/v1/applications/{application.id}/accounts/never_seen"
        )

        assert response.status_code == 400
        assert [error["code"] for error in response.data["errors"]] == ["account_ref_exist"]

    def test_account_of_another_application_is_not_exposed(self, application, second_application, no_geoip):
        audit(application, client_id="their_customer")

        response = self.client_for(second_application).get(
            f"/api/v1/applications/{second_application.id}/accounts/their_customer"
        )

        assert response.status_code == 400

    def test_profile_requires_authentication(self, application, no_geoip):
        from rest_framework.test import APIClient

        audit(application, client_id="someone")

        response = APIClient().get(f"/api/v1/applications/{application.id}/accounts/someone")

        assert response.status_code == 401


class TestEventValidation:
    def test_accepts_counterparty_and_account_age(self):
        from core.models import Policy
        from core.audit.events import TransactionEvent

        event = TransactionEvent(
            id="tx_1", type="debit", amount=10, currency_code="NGN",
            client_id="user_1", counterparty_id="payee_1", account_age_days=3,
        )

        assert event.verify(Policy()) == []

    def test_rejects_malformed_values(self):
        from core.models import Policy
        from core.audit.events import TransactionEvent

        event = TransactionEvent(
            id="tx_1", type="debit", amount=10, currency_code="NGN",
            client_id="user_1", counterparty_id="two words", account_age_days=-4,
        )

        codes = {error.code for error in event.verify(Policy())}

        assert codes == {"void_or_dense_string", "void_or_decimal"}
