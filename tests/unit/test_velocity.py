"""
VelocityCheckRule against recorded history: each window, each count, and
what must not be counted.
"""

import asyncio
from datetime import timedelta
from itertools import count

from django.utils import timezone


serial = count()


def history(application, *, seconds_ago, actor="spender", n=1, outcome=None,
            ip_address="102.91.133.202", device=None, category=None, application_id=None):
    """n past transactions for `actor`, all `seconds_ago` old."""
    from core.audit.logger import AuditLogger
    from core.audit.models import AuditLog, AuditLogCategory, AuditLogLevel

    for _ in range(n):
        log = AuditLogger.log(
            level=AuditLogLevel.INFO,
            category=category or AuditLogCategory.TRANSACTION,
            action="transaction_debit",
            actor_type="client",
            actor_id=actor,
            application_id=application_id or application.id,
            ip_address=ip_address,
            outcome=outcome,
            context=dict(),
        )
        AuditLog.objects.filter(id=log.id).update(
            timestamp=timezone.now() - timedelta(seconds=seconds_ago),
            device_fingerprint=device,
        )


def findings(application, client_id="spender"):
    from core.audit.events import TransactionEvent
    from core.audit.rules import VelocityCheckRule
    from core.audit.scope import Scope

    event = TransactionEvent(
        id=f"tx_{next(serial)}", type="debit", amount=5, currency_code="USD", client_id=client_id,
    )
    rule = VelocityCheckRule(event=event, policy=application.policy, scope=Scope())
    return {message.code: message for message in asyncio.run(rule.execute(False)) or []}


class TestWindows:
    def test_more_than_five_in_a_minute(self, application):
        history(application, seconds_ago=30, n=6)

        assert findings(application)["velocity_exceeded_per_minute"].context["count"] == 6

    def test_five_in_a_minute_is_the_limit_not_over_it(self, application):
        history(application, seconds_ago=30, n=5)

        assert "velocity_exceeded_per_minute" not in findings(application)

    def test_older_than_a_minute_counts_toward_five_minutes_only(self, application):
        history(application, seconds_ago=120, n=16)

        found = findings(application)
        assert "velocity_exceeded_per_minute" not in found
        assert found["velocity_exceeded_per_5_minutes"].context["count"] == 16

    def test_more_than_fifty_in_an_hour(self, application):
        history(application, seconds_ago=1800, n=51)

        found = findings(application)
        assert found["velocity_exceeded_per_hour"].context["count"] == 51
        assert "velocity_exceeded_per_5_minutes" not in found

    def test_more_than_two_hundred_in_a_day(self, application):
        history(application, seconds_ago=6 * 3600, n=201)

        found = findings(application)
        assert found["velocity_exceeded_per_day"].context["count"] == 201
        assert "velocity_exceeded_per_hour" not in found

    def test_older_than_a_day_is_not_counted(self, application):
        history(application, seconds_ago=25 * 3600, n=201)

        assert findings(application) == {}


class TestWithinTheHour:
    def test_more_than_ten_failures(self, application):
        history(application, seconds_ago=1800, n=11, outcome="failure")

        assert findings(application)["high_failure_rate"].context["failed_count"] == 11

    def test_failures_older_than_an_hour_are_not_counted(self, application):
        history(application, seconds_ago=2 * 3600, n=11, outcome="failure")

        assert "high_failure_rate" not in findings(application)

    def test_more_than_five_addresses(self, application):
        for index in range(6):
            history(application, seconds_ago=600, ip_address=f"102.91.133.{index + 1}")

        assert findings(application)["multiple_ips_detected"].context["count"] == 6

    def test_five_addresses_is_the_limit(self, application):
        for index in range(5):
            history(application, seconds_ago=600, n=2, ip_address=f"102.91.133.{index + 1}")

        assert "multiple_ips_detected" not in findings(application)

    def test_more_than_three_devices(self, application):
        for index in range(4):
            history(application, seconds_ago=600, device=f"device_{index}")

        assert findings(application)["multiple_devices_detected"].context["count"] == 4

    def test_events_without_a_device_are_not_a_device(self, application):
        # Three real devices and some events that carried none. The missing
        # device is not a fourth one.
        for index in range(3):
            history(application, seconds_ago=600, device=f"device_{index}")
        history(application, seconds_ago=600, n=3, device=None)

        assert "multiple_devices_detected" not in findings(application)


class TestWhatIsNotCounted:
    def test_another_account(self, application):
        history(application, seconds_ago=30, n=6, actor="someone_else")

        assert findings(application) == {}

    def test_another_application(self, application, second_application):
        history(application, seconds_ago=30, n=6, application_id=second_application.id)

        assert findings(application) == {}

    def test_non_transactions(self, application):
        from core.audit.models import AuditLogCategory

        history(application, seconds_ago=30, n=6, category=AuditLogCategory.AUTHENTICATION)

        assert findings(application) == {}

    def test_an_event_without_an_account(self, application):
        history(application, seconds_ago=30, n=6)

        assert findings(application, client_id=None) == {}


def test_every_window_from_one_history(application):
    # 51 in the last four minutes is over the five-minute and hourly limits,
    # and not over the daily one.
    history(application, seconds_ago=240, n=51)

    found = findings(application)
    assert found["velocity_exceeded_per_5_minutes"].context["count"] == 51
    assert found["velocity_exceeded_per_hour"].context["count"] == 51
    assert "velocity_exceeded_per_day" not in found
    assert "velocity_pace" not in found  # past the ceiling, not pacing toward it
