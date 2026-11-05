"""
What happens after the response reaches the merchant, signed, with retries.

A case opened, a challenge failed an hour later, a campaign that emerged
across twenty requests, a calibration that moved a weight overnight: none of
it fits in the response to the audit that started it. Webhooks carry it. The
merchant's endpoint will be down at some point, so deliveries are rows with
backoff, not fire-and-forget requests, and every delivery goes through the
same SSRF guard as every other outbound call.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from django.utils import timezone

from core.outbound.webhooks import Webhooks


@pytest.fixture
def subscribed(application):
    from core import mcrypt

    application.webhook_url = "https://merchant.example/flit"
    application.webhook_secret = mcrypt.encrypt("whsec_" + "x" * 32)
    application.webhook_events = []
    application.save(update_fields=["webhook_url", "webhook_secret", "webhook_events"])
    return application


class TestSubscription:
    def test_no_url_means_nothing_is_queued(self, application):
        from core.models import WebhookDelivery

        assert Webhooks.enqueue(application, "case.opened", dict(x=1)) is None
        assert WebhookDelivery.objects.count() == 0

    def test_a_url_with_no_event_filter_gets_everything(self, subscribed):
        from core.models import WebhookDelivery

        Webhooks.enqueue(subscribed, "case.opened", dict(x=1))
        Webhooks.enqueue(subscribed, "challenge.failed", dict(x=2))

        assert WebhookDelivery.objects.count() == 2

    def test_an_event_filter_narrows_it(self, subscribed):
        from core.models import WebhookDelivery

        subscribed.webhook_events = ["case.opened"]
        subscribed.save(update_fields=["webhook_events"])

        Webhooks.enqueue(subscribed, "case.opened", dict(x=1))
        Webhooks.enqueue(subscribed, "challenge.failed", dict(x=2))

        assert list(WebhookDelivery.objects.values_list("event", flat=True)) == ["case.opened"]

    def test_unknown_events_are_not_queued(self, subscribed):
        assert Webhooks.enqueue(subscribed, "something.else", {}) is None


class TestSignature:
    def test_the_merchant_can_verify_it(self):
        body = '{"hello":"world"}'
        header = Webhooks.sign("secret", 1_700_000_000, body)

        assert header.startswith("t=1700000000,v1=")
        assert Webhooks.verify_signature("secret", header, body, now=1_700_000_010)

    def test_a_different_body_or_secret_fails(self):
        body = '{"hello":"world"}'
        header = Webhooks.sign("secret", 1_700_000_000, body)

        assert not Webhooks.verify_signature("secret", header, '{"hello":"there"}', now=1_700_000_010)
        assert not Webhooks.verify_signature("other", header, body, now=1_700_000_010)

    def test_a_stale_timestamp_fails(self):
        body = "{}"
        header = Webhooks.sign("secret", 1_700_000_000, body)

        assert not Webhooks.verify_signature("secret", header, body, now=1_700_001_000)

    def test_garbage_fails_quietly(self):
        assert not Webhooks.verify_signature("secret", "nonsense", "{}")
        assert not Webhooks.verify_signature("secret", None, "{}")


def sent(status=200):
    """A patched outbound `send` that records what it was asked to do."""
    calls = []

    async def fake(url, *, method="POST", body=b"", headers=None, timeout=None, **_):
        calls.append(dict(url=url, body=body, headers=headers, timeout=timeout))
        return status, b"ok"

    return calls, patch("core.outbound.webhooks.send", side_effect=fake)


class TestDelivery:
    def test_a_delivery_is_signed_and_marked_delivered(self, subscribed):
        delivery = Webhooks.enqueue(subscribed, "case.opened", dict(case_id="c1"))
        calls, patcher = sent(200)

        with patcher:
            accepted = asyncio.run(Webhooks.deliver(delivery))

        assert accepted
        delivery.refresh_from_db()
        assert delivery.status == "delivered"
        assert delivery.attempts == 1
        assert delivery.last_status_code == 200

        call = calls[0]
        assert call["url"] == "https://merchant.example/flit"
        assert call["headers"]["X-Flit-Event"] == "case.opened"
        assert call["headers"]["X-Flit-Delivery"] == str(delivery.id)
        body = call["body"].decode()
        assert json.loads(body)["data"] == dict(case_id="c1")
        assert Webhooks.verify_signature("whsec_" + "x" * 32, call["headers"]["X-Flit-Signature"], body)

    def test_a_failure_schedules_a_retry_with_backoff(self, subscribed):
        delivery = Webhooks.enqueue(subscribed, "case.opened", {})
        _, patcher = sent(503)

        before = timezone.now()
        with patcher:
            accepted = asyncio.run(Webhooks.deliver(delivery))

        assert not accepted
        delivery.refresh_from_db()
        assert delivery.status == "pending"
        assert delivery.attempts == 1
        assert delivery.next_attempt_at > before
        assert (delivery.next_attempt_at - before).total_seconds() >= 30

    def test_backoff_doubles_and_caps(self):
        assert 30 <= Webhooks.delay(1) <= 30 * 1.25
        assert 60 <= Webhooks.delay(2) <= 60 * 1.25
        assert Webhooks.delay(12) <= 3600 * 1.25

    def test_enough_failures_park_it_dead(self, subscribed):
        from core.models import WebhookDelivery

        delivery = Webhooks.enqueue(subscribed, "case.opened", {})
        delivery.attempts = WebhookDelivery.MAX_ATTEMPTS - 1
        delivery.save()
        _, patcher = sent(500)

        with patcher:
            asyncio.run(Webhooks.deliver(delivery))

        delivery.refresh_from_db()
        assert delivery.status == "dead"

    def test_a_connection_error_is_a_retry(self, subscribed):
        from core.outbound import OutboundError

        delivery = Webhooks.enqueue(subscribed, "case.opened", {})

        with patch("core.outbound.webhooks.send", AsyncMock(side_effect=OutboundError("refused"))):
            asyncio.run(Webhooks.deliver(delivery))

        delivery.refresh_from_db()
        assert delivery.status == "pending"
        assert "refused" in delivery.last_error

    def test_a_url_inside_the_network_is_dead_on_arrival(self, subscribed):
        """Not a transient failure: the URL itself is refused before any socket opens."""
        subscribed.webhook_url = "https://169.254.169.254/latest/"
        subscribed.save(update_fields=["webhook_url"])
        delivery = Webhooks.enqueue(subscribed, "case.opened", {})

        with patch("aiohttp.ClientSession") as session:
            asyncio.run(Webhooks.deliver(delivery))

        session.assert_not_called()
        delivery.refresh_from_db()
        assert delivery.status == "dead"
        assert "refused" in delivery.last_error

    def test_the_command_drains_what_is_due(self, subscribed):
        from io import StringIO
        from django.core.management import call_command
        from core.models import WebhookDelivery

        Webhooks.enqueue(subscribed, "case.opened", {})
        later = Webhooks.enqueue(subscribed, "case.opened", {})
        later.next_attempt_at = timezone.now() + timezone.timedelta(hours=1)
        later.save()
        _, patcher = sent(200)

        out = StringIO()
        with patcher:
            call_command("deliver_webhooks", stdout=out)

        assert "delivered 1, failed 0" in out.getvalue()
        assert WebhookDelivery.objects.filter(status="pending").count() == 1


class TestEventsThatReachTheWebhook:
    def test_a_case_opening_is_queued(self, subscribed, no_geoip):
        from core.models import WebhookDelivery
        from tests.unit.test_console import risky_audit

        risky_audit(subscribed)

        events = set(WebhookDelivery.objects.values_list("event", flat=True))
        assert "case.opened" in events

    def test_a_block_is_queued(self, subscribed, no_geoip):
        from core.models import WebhookDelivery
        from tests.unit.test_block_streak import block_range, blocked_signup

        block_range(subscribed)
        blocked_signup(subscribed, "probe_1", send_alerts=True)

        assert WebhookDelivery.objects.filter(event="decision.blocked").exists()

    def test_a_challenge_outcome_is_queued(self, subscribed):
        from core.models import WebhookDelivery
        from tests.unit.test_challenges import issue, verify

        challenge, code = issue(subscribed)
        verify(challenge, code)

        delivery = WebhookDelivery.objects.get(event="challenge.passed")
        assert delivery.payload["challenge_id"] == str(challenge.id)


class TestDecisionHook:
    """The merchant's own logic gets a vote, and may only tighten."""

    def hooked(self, application, timeout_ms=150):
        application.decision_hook_url = "https://merchant.example/decide"
        application.decision_hook_timeout_ms = timeout_ms
        application.save(update_fields=["decision_hook_url", "decision_hook_timeout_ms"])
        return application

    def answer(self, body, status=200):
        async def fake(url, **kwargs):
            return status, json.dumps(body).encode() if isinstance(body, dict) else body
        return patch("core.outbound.decision_hook.send", side_effect=fake)

    def transfer(self, application):
        from tests.unit.test_decision_rules import transfer
        return transfer(application)

    def test_a_hook_can_tighten_allow_to_block(self, application, no_geoip):
        self.hooked(application)

        with self.answer(dict(decision="block", reason="card reported lost")):
            result = self.transfer(application)

        assert result.should_block is True
        assert result.hook["applied"] is True
        assert result.hook["before"] == "allow"
        assert result.hook["after"] == "block"
        assert result.hook["reason"] == "card reported lost"

    def test_a_hook_cannot_loosen(self, application, no_geoip):
        from tests.unit.test_decision_rules import set_rules, rule

        self.hooked(application)
        set_rules(application.policy, block=[rule("ip", "102.91.133.202")])

        with self.answer(dict(decision="allow", reason="trusted")):
            result = self.transfer(application)

        assert result.should_block is True
        assert result.hook["applied"] is False
        assert result.hook["decision"] == "allow"

    def test_a_timeout_is_ignored_and_recorded(self, application, no_geoip):
        from core.outbound import OutboundError

        self.hooked(application)

        with patch("core.outbound.decision_hook.send", AsyncMock(side_effect=OutboundError("timeout"))):
            result = self.transfer(application)

        assert result.should_block is False
        assert result.hook["applied"] is False
        assert "timeout" in result.hook["error"]

    def test_a_bad_answer_is_ignored(self, application, no_geoip):
        self.hooked(application)

        with self.answer(b"<html>oops</html>", status=200):
            result = self.transfer(application)

        assert result.hook["applied"] is False
        assert result.hook["error"]

    def test_the_hook_is_on_the_record(self, application, no_geoip):
        from core.models import AuditLog

        self.hooked(application)

        with self.answer(dict(decision="review", reason="staff watchlist")):
            result = self.transfer(application)

        log = AuditLog.objects.get(id=result.audit_id)
        assert log.context["hook"]["applied"] is True
        assert log.context["hook"]["after"] == "review"
        assert result.should_review is True

    def test_shadow_still_applies_after_the_hook(self, application, no_geoip):
        application.enforcement = "shadow"
        application.save(update_fields=["enforcement"])
        self.hooked(application)

        with self.answer(dict(decision="block")):
            result = self.transfer(application)

        assert result.would_block is True
        assert result.should_block is False
