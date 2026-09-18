"""
Database-backed tests for FLIT's device graph.

Covers persisting audits, linking devices to accounts, the multi-accounting,
account-sharing and device-tampering rules, the checks that only work once
history exists (velocity), and the outcome and device lookup endpoints.
"""

import asyncio
from unittest.mock import AsyncMock, patch


def make_visit(visitor_id="visitor_1", **overrides):
    """What FetchVisitData.normalize_visit_data returns."""
    from devkit.struct import Struct

    attributes = dict(
        raw_data={},
        fingerprint=visitor_id,
        city="Lagos",
        state="Lagos",
        country="Nigeria",
        latitude=6.5,
        longitude=3.3,
        ip="81.2.69.160",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        asn="AS4766",
        asn_org="Example Telecom",
        is_datacenter=False,
        vpn=False,
        proxy=False,
        tor=False,
        ip_blocklisted=False,
        incognito=False,
        bot="notDetected",
        device_signals={},
        suspect_score=0,
    )
    attributes.update(overrides)
    return Struct(**attributes)


def audit(event, application, visit=None, **options):
    """Run Auditor.audit with Fingerprint stubbed out."""
    from core.audit.auditor import Auditor

    options.setdefault("send_alerts", False)

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=visit),
    ):
        return asyncio.run(Auditor.audit(event, application.policy, **options))


def transaction(**attributes):
    from core.audit.events import TransactionEvent

    attributes.setdefault("id", "tx_1")
    attributes.setdefault("type", "debit")
    attributes.setdefault("amount", 25)
    attributes.setdefault("currency_code", "NGN")
    return TransactionEvent(**attributes)


class TestAuditPersistence:
    def test_audit_is_recorded(self, application):
        from core.models import AuditLog

        result = audit(
            transaction(
                client_id="user_1",
                visit_id="visit_1",
                ip_address="81.2.69.160",
                status="failed",
            ),
            application,
            visit=make_visit(),
        )

        log = AuditLog.objects.get(id=result.audit_id)
        assert log.actor_id == "user_1"
        assert log.resource_id == "tx_1"
        assert log.action == "transaction_debit"
        assert log.category == "transaction"
        assert log.outcome == "failure"
        assert log.device_fingerprint == "visitor_1"
        assert log.risk_score == result.risk_score
        assert log.context["device_id"] == result.device_id
        assert log.verify_integrity()

    def test_recording_can_be_skipped(self, application):
        from core.models import AuditLog

        result = audit(transaction(client_id="user_1"), application, record=False)

        assert result.audit_id is None
        assert AuditLog.objects.count() == 0

    def test_a_failing_recorder_does_not_fail_the_audit(self, application):
        from core.models import AuditLog

        with patch(
            "core.audit.recorder.AuditLogger.log",
            side_effect=RuntimeError("database is down"),
        ):
            result = audit(transaction(client_id="user_1"), application)

        assert result.audit_id is None
        assert result.risk_level
        assert AuditLog.objects.count() == 0

    def test_client_event_is_recorded_as_authentication(self, application):
        from core.models import AuditLog
        from core.audit.events import ClientEvent

        result = audit(
            ClientEvent(id="user_1", action="password_change", visit_id="visit_1"),
            application,
            visit=make_visit(),
        )

        log = AuditLog.objects.get(id=result.audit_id)
        assert log.category == "authentication"
        assert log.action == "password_change"
        assert log.actor_id == "user_1"


class TestDeviceGraph:
    def test_device_and_account_link_are_created(self, application):
        from core.models import DeviceIdentity, DeviceAccountLink

        audit(transaction(client_id="user_1", visit_id="visit_1"), application, visit=make_visit())
        audit(transaction(client_id="user_1", visit_id="visit_1"), application, visit=make_visit())

        device = DeviceIdentity.objects.get(external_id="visitor_1")
        assert device.source == "fingerprint"
        assert device.event_count == 2
        assert device.last_country == "Nigeria"

        link = DeviceAccountLink.objects.get(device=device, client_id="user_1")
        assert link.event_count == 2
        assert DeviceAccountLink.objects.count() == 1

    def test_device_flags_come_from_smart_signals(self, application):
        from core.models import DeviceIdentity

        audit(
            transaction(client_id="user_1", visit_id="visit_1"),
            application,
            visit=make_visit(device_signals={"jailbroken": True, "emulator": False}),
        )

        assert DeviceIdentity.objects.get(external_id="visitor_1").flags == ["jailbroken"]

    def test_devices_without_a_visit_are_not_resolved(self, application):
        from core.models import DeviceIdentity

        result = audit(transaction(client_id="user_1"), application)

        assert result.device_id is None
        assert DeviceIdentity.objects.count() == 0


class TestMultiAccountingRule:
    def use_device(self, application, client_id):
        return audit(
            transaction(client_id=client_id, visit_id="visit_1"),
            application,
            visit=make_visit(),
        )

    def test_flags_a_device_shared_by_too_many_accounts(self, application):
        for index in range(1, 4):
            result = self.use_device(application, f"user_{index}")
            assert "multi_accounting" not in result.factors

        result = self.use_device(application, "user_4")

        assert "multi_accounting" in result.factors
        message = next(m for m in result.reasons if m.code == "multi_accounting")
        assert message.context["accounts"] == 4
        assert message.context["limit"] == 3

    def test_threshold_comes_from_the_policy(self, application):
        application.policy.device_thresholds = {"max_accounts_per_device": 1}
        application.policy.save()
        application.refresh_from_db()

        self.use_device(application, "user_1")
        result = self.use_device(application, "user_2")

        assert "multi_accounting" in result.factors


class TestAccountSharingRule:
    def use_devices(self, application, count, client_id="user_1"):
        result = None
        for index in range(1, count + 1):
            result = audit(
                transaction(client_id=client_id, visit_id=f"visit_{index}"),
                application,
                visit=make_visit(visitor_id=f"visitor_{index}"),
            )
        return result

    def test_flags_an_account_used_from_several_devices_at_once(self, application):
        assert "concurrent_devices" not in self.use_devices(application, 2).factors

        result = self.use_devices(application, 3)

        assert "concurrent_devices" in result.factors
        message = next(m for m in result.reasons if m.code == "concurrent_devices")
        assert message.context["devices"] == 3

    def test_older_device_use_counts_as_sharing_not_concurrency(self, application):
        from datetime import timedelta
        from django.utils import timezone
        from core.models import DeviceAccountLink

        self.use_devices(application, 4)

        # Age every link except the current device out of the 1 hour window.
        (
            DeviceAccountLink.objects
            .exclude(device__external_id="visitor_4")
            .update(last_seen_at=timezone.now() - timedelta(hours=2))
        )

        result = audit(
            transaction(client_id="user_1", visit_id="visit_4"),
            application,
            visit=make_visit(visitor_id="visitor_4"),
        )

        assert "concurrent_devices" not in result.factors
        assert "account_sharing" in result.factors


class TestDeviceTamperingRule:
    def test_flags_integrity_signals(self, application):
        result = audit(
            transaction(client_id="user_1", visit_id="visit_1"),
            application,
            visit=make_visit(
                device_signals={
                    "jailbroken": True,
                    "hooking_framework": True,
                    "emulator": False,
                    "tampering": None,
                },
                suspect_score=31,
            ),
        )

        assert "jailbroken_device" in result.factors
        assert "hooking_framework" in result.factors
        assert "emulator" not in result.factors
        assert "device_tampering" not in result.factors
        assert result.risk_level in ("high", "critical")

    def test_clean_device_raises_no_integrity_signal(self, application):
        result = audit(
            transaction(client_id="user_1", visit_id="visit_1"),
            application,
            visit=make_visit(),
        )

        assert not [code for code in result.factors if code in ("jailbroken_device", "emulator")]


class TestHistoryDependentRules:
    def test_velocity_rule_fires_once_history_exists(self, application):
        result = None
        for index in range(7):
            result = audit(
                transaction(id=f"tx_{index}", client_id="user_1"),
                application,
            )

        assert "velocity_exceeded_per_minute" in result.factors

    def test_historical_scores_are_read_back(self, application):
        for index in range(3):
            audit(transaction(id=f"tx_{index}", client_id="user_1"), application)

        from core.scoring import RiskEngine

        scores = asyncio.run(
            RiskEngine().get_historical_scores(
                actor_id="user_1",
                application_id=application.id,
            )
        )

        assert len(scores) == 3


class TestOutcomeAndDeviceEndpoints:
    def client_for(self, application):
        from rest_framework.test import APIClient
        from core.auth.actor import Actor

        client = APIClient()
        client.force_authenticate(user=None, token=Actor(application))
        return client

    def audited(self, application):
        return audit(
            transaction(client_id="user_1", visit_id="visit_1"),
            application,
            visit=make_visit(),
        )

    def test_label_an_audit_by_audit_id(self, application):
        from core.models import AuditLog

        result = self.audited(application)
        client = self.client_for(application)

        response = client.post(
            f"/api/v1/applications/{application.id}/outcomes",
            dict(audit_id=result.audit_id, label="fraud"),
            format="json",
        )

        assert response.status_code == 200, response.data
        assert response.data["data"]["label"] == "fraud"

        log = AuditLog.objects.get(id=result.audit_id)
        assert log.label == "fraud"
        assert log.labeled_at is not None

    def test_label_an_audit_by_event_id(self, application):
        from core.models import AuditLog

        self.audited(application)
        client = self.client_for(application)

        response = client.post(
            f"/api/v1/applications/{application.id}/outcomes",
            dict(event_id="tx_1", label="chargeback"),
            format="json",
        )

        assert response.status_code == 200, response.data
        assert AuditLog.objects.get(resource_id="tx_1").label == "chargeback"

    def test_rejects_an_unknown_label(self, application):
        result = self.audited(application)
        client = self.client_for(application)

        response = client.post(
            f"/api/v1/applications/{application.id}/outcomes",
            dict(audit_id=result.audit_id, label="probably_fine"),
            format="json",
        )

        assert response.status_code == 400
        assert [error["code"] for error in response.data["errors"]] == ["in_choices"]

    def test_device_lookup_returns_accounts_and_history(self, application):
        result = self.audited(application)
        audit(
            transaction(id="tx_2", client_id="user_2", visit_id="visit_1"),
            application,
            visit=make_visit(device_signals={"emulator": True}),
        )

        client = self.client_for(application)
        response = client.get(f"/api/v1/applications/{application.id}/devices/{result.device_id}")

        assert response.status_code == 200, response.data
        device = response.data["data"]["device"]
        assert device["account_count"] == 2
        assert {account["client_id"] for account in device["accounts"]} == {"user_1", "user_2"}
        assert device["flags"] == ["emulator"]
        assert len(device["recent_events"]) == 2
        assert 0 <= device["trust_score"] <= 1

    def test_device_of_another_application_is_not_exposed(self, application):
        from core.models import User, Organization, Application

        result = self.audited(application)

        other_owner = User.objects.create_user(email="other@flit.io", password="x" * 12)
        other_org = Organization.objects.create(name="Other Org", owner=other_owner)
        other_app = Application.objects.create(name="Other App", organization=other_org)

        client = self.client_for(other_app)
        response = client.get(f"/api/v1/applications/{other_app.id}/devices/{result.device_id}")

        assert response.status_code == 400
        assert [error["code"] for error in response.data["errors"]] == ["device_ref_exist"]

    def test_authentication_is_required(self, application):
        from rest_framework.test import APIClient

        result = self.audited(application)
        response = APIClient().get(
            f"/api/v1/applications/{application.id}/devices/{result.device_id}"
        )

        assert response.status_code == 401
