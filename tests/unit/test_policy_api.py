"""
The policy can be changed from the console, and the direction matters.

An application key lives on the merchant's servers; if it leaks, the first
thing an attacker does with it is raise the block threshold. So anyone with
the key may make FLIT stricter, and only a signed-in owner may make it
looser. Every change is on the audit chain, and a loosening says so.
"""

import pytest


def app_client(application):
    from rest_framework.test import APIClient
    from core.auth.actor import Actor

    client = APIClient()
    client.force_authenticate(user=None, token=Actor(application))
    return client


def owner_client(application):
    from rest_framework.test import APIClient
    from core.auth.actor import Actor

    client = APIClient()
    client.force_authenticate(user=None, token=Actor(application.organization.owner))
    return client


def policy_url(application):
    return f"/api/v1/applications/{application.id}/policy"


class TestReadingThePolicy:
    def test_the_defaults_are_reported(self, application):
        response = app_client(application).get(policy_url(application))
        data = response.data["data"]

        assert response.status_code == 200
        assert data["thresholds"] == dict(block_at=0.7, review_at=0.5, challenge_at=0.45)
        assert data["rules"] == dict(block=[], review=[], challenge=[], allow=[])
        assert data["disabled_rules"] == []
        assert data["latency_budget_ms"] == 3000
        assert data["effective"]["thresholds"]["block_at"] == 0.7
        assert data["organization"] is None


class TestTightening:
    def test_an_application_key_may_tighten(self, application):
        from core.models import AuditLog

        response = app_client(application).patch(policy_url(application), dict(
            thresholds=dict(block_at=0.6),
            rules=dict(block=[dict(subject="cidr", pattern="41.58.100.0/24", reason="actor")]),
            disabled_rules=[],
        ), format="json")

        assert response.status_code == 200
        application.policy.refresh_from_db()
        assert application.policy.calibration["thresholds"]["block_at"] == 0.6
        assert application.policy.rules["block"][0]["pattern"] == "41.58.100.0/24"

        log = AuditLog.objects.filter(application_id=application.id, action="policy_updated").get()
        assert log.context["loosened"] == []
        assert log.actor_type == "application"

    def test_the_change_takes_effect_on_the_next_decision(self, application, no_geoip):
        from tests.unit.test_decision_rules import transfer

        app_client(application).patch(policy_url(application), dict(
            rules=dict(block=[dict(subject="ip", pattern="41.58.100.5")]),
        ), format="json")
        application.policy.refresh_from_db()

        assert transfer(application, ip_address="41.58.100.5").should_block is True


class TestLoosening:
    def tighten_first(self, application):
        app_client(application).patch(policy_url(application), dict(
            rules=dict(block=[dict(subject="ip", pattern="41.58.100.5")]),
        ), format="json")

    @pytest.mark.parametrize("body", [
        dict(thresholds=dict(block_at=0.9)),
        dict(thresholds=dict(review_at=0.6)),
        dict(rules=dict(block=[])),
        dict(rules=dict(block=[dict(subject="ip", pattern="41.58.100.5")], allow=[dict(subject="client_id", pattern="*")])),
        dict(disabled_rules=["SanctionedAddressRule"]),
        dict(weights=dict(account_takeover_risk=0.1)),
    ])
    def test_an_application_key_is_refused(self, application, body):
        self.tighten_first(application)

        response = app_client(application).patch(policy_url(application), body, format="json")

        assert response.status_code == 403
        assert response.data["errors"][0]["code"] == "policy_loosening_forbidden"
        assert response.data["errors"][0]["context"]["loosened"]

    def test_nothing_was_changed_by_the_refusal(self, application):
        self.tighten_first(application)
        app_client(application).patch(policy_url(application), dict(thresholds=dict(block_at=0.9)), format="json")

        application.policy.refresh_from_db()
        assert application.policy.calibration["thresholds"]["block_at"] == 0.7
        assert application.policy.rules["block"]

    def test_the_owner_may_loosen_and_it_is_on_the_record(self, application):
        from core.models import AuditLog

        self.tighten_first(application)
        response = owner_client(application).patch(policy_url(application), dict(
            thresholds=dict(block_at=0.9), rules=dict(block=[]),
        ), format="json")

        assert response.status_code == 200
        log = AuditLog.objects.filter(application_id=application.id, action="policy_loosened").get()
        assert log.level == "warning"
        assert any("block_at raised" in item for item in log.context["loosened"])
        assert any("block rule removed" in item for item in log.context["loosened"])
        assert log.actor_type == "user"

    def test_a_stranger_cannot_touch_it_at_all(self, application, second_application):
        from rest_framework.test import APIClient
        from core.auth.actor import Actor

        client = APIClient()
        client.force_authenticate(user=None, token=Actor(second_application.organization.owner))

        response = client.patch(policy_url(application), dict(thresholds=dict(block_at=0.6)), format="json")

        assert response.status_code in (401, 403)


class TestPoisonGuards:
    def test_empty_or_zero_weights_are_refused(self, application):
        for weights in ({}, dict(account_takeover_risk=0.0, bot_detected=0)):
            response = owner_client(application).patch(policy_url(application), dict(weights=weights), format="json")
            assert response.status_code == 400
            assert response.data["errors"][0]["code"] == "weights_empty"

    def test_bad_rules_name_their_path(self, application):
        response = app_client(application).patch(policy_url(application), dict(
            rules=dict(block=[dict(subject="cidr", pattern="nope")]),
        ), format="json")

        assert response.status_code == 400
        assert response.data["errors"][0]["path"] == "rules.block[0].pattern"

    def test_the_latency_budget_has_a_floor(self, application):
        response = app_client(application).patch(policy_url(application), dict(latency_budget_ms=5), format="json")
        assert response.status_code == 400


class TestOrganizationPolicyApi:
    def url(self, application):
        return f"/api/v1/organizations/{application.organization_id}/policy"

    def test_the_owner_sets_the_estate_policy(self, application, no_geoip):
        from core.models import AuditLog
        from tests.unit.test_decision_rules import transfer

        response = owner_client(application).patch(self.url(application), dict(
            rules=dict(block=[dict(subject="cidr", pattern="41.58.100.0/24")]),
            max_block_at=0.6,
            required_enforcement="enforcing",
            disabled_rules=["BotSignalRule"],
        ), format="json")

        assert response.status_code == 200
        data = response.data["data"]
        assert data["max_block_at"] == 0.6
        assert data["required_enforcement"] == "enforcing"
        application.policy.refresh_from_db()
        assert transfer(application, ip_address="41.58.100.5").should_block is True

        described = app_client(application).get(policy_url(application)).data["data"]
        assert described["effective"]["thresholds"]["block_at"] == 0.6
        assert described["organization"]["disabled_rules"] == ["BotSignalRule"]
        # Disabling a rule across the estate is a loosening, and the record says so.
        log = AuditLog.objects.filter(action="organization_policy_loosened").get()
        assert any("rule disabled: BotSignalRule" in item for item in log.context["loosened"])

    def test_an_application_key_cannot_read_or_write_it(self, application):
        client = app_client(application)
        assert client.get(self.url(application)).status_code in (401, 403)
        assert client.patch(self.url(application), dict(max_block_at=0.9), format="json").status_code in (401, 403)

    def test_another_owner_cannot_either(self, application, second_application):
        response = owner_client(second_application).patch(self.url(application), dict(max_block_at=0.9), format="json")
        assert response.status_code in (401, 403)

    def test_lifting_the_ceiling_is_recorded_as_a_loosening(self, application):
        from core.models import AuditLog

        owner_client(application).patch(self.url(application), dict(max_block_at=0.6), format="json")
        owner_client(application).patch(self.url(application), dict(max_block_at=None), format="json")

        assert AuditLog.objects.filter(action="organization_policy_loosened").exists()


class TestCalibrationRollback:
    def applied_run(self, application):
        from core.models import CalibrationRun, CalibrationMode

        policy = application.policy
        policy.calibration = dict(weights=dict(bot_detected=0.8, datacenter_ip=0.35))
        policy.save(update_fields=["calibration"])

        return CalibrationRun.objects.create(
            application=application, window_days=30, mode=CalibrationMode.APPLIED,
            applied=True, proposals=[
                dict(code="bot_detected", **{"from": 0.7, "to": 0.8}, accepted=True),
                dict(code="datacenter_ip", **{"from": 0.3, "to": 0.35}, accepted=True),
                dict(code="vpn_detected", **{"from": 0.4, "to": 0.5}, accepted=False),
            ],
        )

    def test_rollback_restores_the_weights_the_run_moved(self, application):
        from core.calibration import Calibrator
        from core.models import CalibrationMode

        run = self.applied_run(application)
        reversal = Calibrator.rollback(run)

        application.policy.refresh_from_db()
        weights = application.policy.calibration["weights"]
        # datacenter_ip went back to its default, so the override is gone;
        # bot_detected has no named default, so its prior value is kept.
        assert "datacenter_ip" not in weights
        assert weights["bot_detected"] == 0.7
        assert reversal.mode == CalibrationMode.ROLLED_BACK
        run.refresh_from_db()
        assert run.mode == CalibrationMode.ROLLED_BACK

    def test_only_an_applied_run_can_be_rolled_back(self, application):
        from core.calibration import Calibrator
        from core.models import CalibrationRun

        run = CalibrationRun.objects.create(application=application, window_days=30)
        with pytest.raises(ValueError):
            Calibrator.rollback(run)

    def test_the_command(self, application):
        from io import StringIO
        from django.core.management import call_command

        run = self.applied_run(application)
        out = StringIO()
        call_command("calibrate", rollback=str(run.id), stdout=out)

        assert "Rolled back" in out.getvalue()


class TestOutboundSettings:
    def test_webhook_and_decision_hook_are_set_through_the_policy(self, application):
        response = app_client(application).patch(policy_url(application), dict(
            webhook=dict(url="https://merchant.example/flit", secret="whsec_" + "x" * 32, events=["case.opened"]),
            decision_hook=dict(url="https://merchant.example/decide", timeout_ms=200),
            challenge_method="otp",
            shadow_rules=[],
        ), format="json")

        assert response.status_code == 200
        data = response.data["data"]
        assert data["webhook"] == dict(url="https://merchant.example/flit", secret_configured=True, events=["case.opened"])
        assert data["decision_hook"] == dict(url="https://merchant.example/decide", timeout_ms=200)
        assert data["challenge_method"] == "otp"

        application.refresh_from_db()
        assert application.raw_webhook_secret == "whsec_" + "x" * 32

    def test_a_private_url_is_refused_at_write_time(self, application):
        for url in ("https://169.254.169.254/", "http://merchant.example/flit", "https://user:pw@merchant.example/"):
            response = app_client(application).patch(policy_url(application), dict(webhook=dict(url=url)), format="json")
            assert response.status_code == 400, url
            assert response.data["errors"][0]["code"] == "outbound_url"

    def test_unknown_events_are_refused(self, application):
        response = app_client(application).patch(policy_url(application), dict(
            webhook=dict(url="https://merchant.example/flit", events=["everything"]),
        ), format="json")
        assert response.status_code == 400

    def test_null_removes_them(self, application):
        client = app_client(application)
        client.patch(policy_url(application), dict(
            webhook=dict(url="https://merchant.example/flit"), decision_hook=dict(url="https://merchant.example/decide"),
        ), format="json")
        response = client.patch(policy_url(application), dict(webhook=None, decision_hook=None), format="json")

        assert response.data["data"]["webhook"] is None
        assert response.data["data"]["decision_hook"] is None
