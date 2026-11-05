"""
The attacker's own failed attempts become evidence, and one campaign is one
case.

A loop that is blocked reads the block and tries the next variation. Scoring
each attempt from zero hands it unlimited attempts. The streak is the memory:
three blocks in a row from one origin raise the next event, open one
high-priority case that counts them, and alert — instead of two hundred
cases nobody can read.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from django.utils import timezone

from core.services.block_streak import BlockStreak


@pytest.fixture(autouse=True)
def clear_cache():
    from django.core.cache import cache
    cache.clear()
    yield
    cache.clear()


def audit(application, event, send_alerts=False):
    from core.audit.auditor import Auditor

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=None),
    ):
        return asyncio.run(Auditor.audit(event, application.policy, send_alerts=send_alerts))


def blocked_signup(application, client_id, ip_address="41.58.100.5", send_alerts=False):
    """A registration FLIT blocks outright, via a policy block on the range."""
    from core.audit.events import RegistrationEvent

    return audit(application, RegistrationEvent(
        id=client_id, client_id=client_id, email=f"{client_id}@example.com", country="US",
        ip_address=ip_address, user_agent="curl/8.5.0", action="registration",
    ), send_alerts=send_alerts)


def clean_transfer(application, client_id, ip_address="41.58.100.5"):
    from core.audit.events import TransactionEvent

    return audit(application, TransactionEvent(
        id=f"tx_{client_id}_{timezone.now().timestamp()}", type="debit", amount=5,
        currency_code="USD", client_id=client_id, ip_address=ip_address,
        user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0",
    ))


def block_range(application, cidr="41.58.100.0/24"):
    policy = application.policy
    policy.rules = dict(block=[dict(subject="cidr", pattern=cidr)])
    policy.save(update_fields=["rules"])
    policy.refresh_from_db()


class TestBlockStreak:
    def test_blocks_build_a_streak_and_a_total(self):
        app = "app"
        assert BlockStreak.read(app, "ip:1.1.1.1") == dict(consecutive=0, total_24h=0)
        BlockStreak.record(app, "ip:1.1.1.1", True)
        BlockStreak.record(app, "ip:1.1.1.1", True)
        assert BlockStreak.read(app, "ip:1.1.1.1") == dict(consecutive=2, total_24h=2)

    def test_an_allow_ends_the_streak_but_not_the_total(self):
        BlockStreak.record("app", "ip:1.1.1.1", True)
        BlockStreak.record("app", "ip:1.1.1.1", True)
        BlockStreak.record("app", "ip:1.1.1.1", False)
        assert BlockStreak.read("app", "ip:1.1.1.1") == dict(consecutive=0, total_24h=2)

    def test_origins_and_applications_are_separate(self):
        BlockStreak.record("app_a", "ip:1.1.1.1", True)
        assert BlockStreak.read("app_b", "ip:1.1.1.1")["consecutive"] == 0
        assert BlockStreak.read("app_a", "ip:2.2.2.2")["consecutive"] == 0

    def test_no_origin_is_nothing(self):
        assert BlockStreak.record("app", None, True) == dict(consecutive=0, total_24h=0)

    def test_the_device_is_preferred_as_origin(self):
        assert BlockStreak.origin_for(device_fingerprint="fp", ip_address="1.1.1.1") == "device:fp"
        assert BlockStreak.origin_for(ip_address="1.1.1.1", client_id="u") == "ip:1.1.1.1"
        assert BlockStreak.origin_for(client_id="u") == "account:u"
        assert BlockStreak.origin_for() is None


class TestBlockStreakRule:
    def test_the_third_attempt_carries_the_first_two(self, application, no_geoip):
        """Two blocked signups from one address; the next event from it is raised."""
        block_range(application)
        blocked_signup(application, "probe_1")
        blocked_signup(application, "probe_2")

        # Lift the block so the next event is scored on its own merits.
        application.policy.rules = {}
        application.policy.save(update_fields=["rules"])
        application.policy.refresh_from_db()

        result = clean_transfer(application, "probe_3")

        assert "block_streak" in result.factors
        assert result.block_streak == 0  # this one was not blocked, so the streak reset
        assert result.risk_score > 0

    def test_one_block_says_nothing(self, application, no_geoip):
        block_range(application)
        blocked_signup(application, "probe_1")

        application.policy.rules = {}
        application.policy.save(update_fields=["rules"])
        application.policy.refresh_from_db()

        result = clean_transfer(application, "probe_2")

        assert "block_streak" not in result.factors

    def test_a_different_address_starts_clean(self, application, no_geoip):
        block_range(application)
        blocked_signup(application, "probe_1")
        blocked_signup(application, "probe_2")

        result = clean_transfer(application, "honest", ip_address="102.91.133.202")

        assert "block_streak" not in result.factors

    def test_the_decision_reports_the_streak(self, application, no_geoip):
        block_range(application)
        first = blocked_signup(application, "probe_1")
        second = blocked_signup(application, "probe_2")

        assert first.block_streak == 1
        assert second.block_streak == 2

    def test_shadow_learns_streaks_too(self, application, no_geoip):
        application.enforcement = "shadow"
        application.save(update_fields=["enforcement"])
        block_range(application)
        blocked_signup(application, "probe_1")
        result = blocked_signup(application, "probe_2")

        assert result.should_block is False
        assert result.block_streak == 2


class TestCampaignCases:
    def test_decisions_from_one_origin_land_on_one_case(self, application, no_geoip):
        from core.models import Case

        block_range(application)
        for index in range(4):
            blocked_signup(application, f"probe_{index}")

        cases = Case.objects.filter(application=application)
        assert cases.count() == 1
        case = cases.get()
        assert case.campaign_key == "ip:41.58.100.5"
        assert case.decision_count == 4
        assert case.decisions().count() == 4

    def test_different_origins_are_different_cases(self, application, no_geoip):
        from core.models import Case

        block_range(application, "41.58.100.0/24")
        blocked_signup(application, "a", ip_address="41.58.100.5")
        blocked_signup(application, "b", ip_address="41.58.100.6")

        assert Case.objects.filter(application=application).count() == 2

    def test_a_closed_case_does_not_absorb_new_decisions(self, application, no_geoip):
        from core.models import Case

        block_range(application)
        blocked_signup(application, "probe_1")
        Case.objects.get(application=application).resolve(status="confirmed_fraud")
        blocked_signup(application, "probe_2")

        assert Case.objects.filter(application=application).count() == 2

    def test_a_blocked_decision_opens_a_high_priority_case(self, application, no_geoip):
        from core.models import Case

        block_range(application)
        blocked_signup(application, "probe_1")

        assert Case.objects.get(application=application).priority == "high"

    def test_a_campaign_raises_the_priority_of_an_ordinary_case(self, application, no_geoip):
        from core.audit.recorder import AuditRecorder
        from core.scoring import RiskEngine

        result = RiskEngine().calculate_risk([dict(code="datacenter_ip", text="", context={})])
        assert AuditRecorder.priority(result, dict(consecutive=0)) == "normal"
        assert AuditRecorder.priority(result, dict(consecutive=3)) == "high"

    def test_the_queue_shows_the_campaign(self, application, no_geoip):
        from rest_framework.test import APIClient
        from core.auth.actor import Actor

        block_range(application)
        for index in range(3):
            blocked_signup(application, f"probe_{index}")

        client = APIClient()
        client.force_authenticate(user=None, token=Actor(application))
        response = client.get(f"/api/v1/applications/{application.id}/cases")

        case = response.data["data"]["cases"][0]
        assert case["decision_count"] == 3
        assert case["priority"] == "high"
        assert case["campaign_key"] == "ip:41.58.100.5"


class TestCampaignAlert:
    def test_the_third_consecutive_block_alerts_once(self, application, no_geoip):
        from core.realtime.alerts import AlertManager

        sent = []

        async def capture(alert):
            sent.append(alert)

        block_range(application)
        with patch.object(AlertManager, "send_alert", AsyncMock(side_effect=capture)):
            for index in range(4):
                blocked_signup(application, f"probe_{index}", send_alerts=True)

        campaign = [a for a in sent if a.context.get("kind") == "campaign_detected"]
        assert len(campaign) == 1
        assert campaign[0].context["consecutive"] == 3
        assert campaign[0].organization_id == str(application.organization_id)
