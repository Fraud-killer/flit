"""
Four findings from review, each closed with a test that would have caught it.

1. A passed challenge could turn any scored block into a review, from any
   account sharing the IP. Now: actor keys only, voided by fraud or failure,
   never applied at or above the block line.
2. Backtest evidence derived from the labelled features was claimed as a
   measured rung. Now: the ledger records the label source, marks circular
   codes, and the gate refuses them.
3. Four merchants on one IP blocked a clean browser user, and nothing a
   merchant reported could offset it. Now: organizations are the unit, failed
   challenges expire, favourable reports count, and shared keys alone cap
   under the block line.
4. Triage's safeguards were softer than described. Now: proposals are hidden
   on open cases, outcomes trip the breaker, auto-clears label nothing.
"""

import pytest

from tests.unit.test_console import risky_audit
from tests.unit.test_protection_network import make_application, key_for, report_fraud, lookup, SHARED_IP
from tests.unit.test_signup_defence import BROWSER, register, make_visit, codes


def favour(application, key, outcome, count=1):
    from core.services.network_reputation import NetworkReputation
    NetworkReputation.record(identity_key_ids=[key.id], application=application, outcome=outcome, count=count)


class TestAPassCannotCancelABlock:
    def test_the_engine_never_discounts_a_blocking_score(self):
        from core.scoring import RiskEngine

        engine = RiskEngine()
        blocking = [dict(code="account_takeover_risk", text="", context={})]
        passed = [dict(code="recent_challenge_passed", text="", context=dict(score=0.0, passed_challenge=True))]

        before = engine.calculate_risk(blocking)
        after = engine.calculate_risk(blocking + passed)
        assert before.should_block
        assert after.should_block, "a pass must not move a score that blocks"
        assert after.total_score == before.total_score

    def test_a_pass_still_discounts_a_sub_block_score(self):
        from core.scoring import RiskEngine, RiskWeights

        engine = RiskEngine(weights=RiskWeights(velocity_pace=0.5))
        borderline = [dict(code="velocity_pace", text="", context={})]
        passed = [dict(code="recent_challenge_passed", text="", context=dict(score=0.0, passed_challenge=True))]

        before = engine.calculate_risk(borderline)
        after = engine.calculate_risk(borderline + passed)
        assert before.should_challenge
        assert not after.should_challenge and after.total_score < before.total_score

    def test_a_pass_on_a_shared_ip_does_not_vouch_for_another_account(self, application, no_geoip):
        from core.models import Challenge
        from tests.unit.test_challenges import verify
        from tests.unit.test_challenge_replay import signup

        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        first = signup(application, client_id="payer_1")
        verify(Challenge.objects.get(id=first.challenge["id"]), first.challenge["code"])

        # Same IP, a different account and email: a stranger on the same network.
        other = signup(application, client_id="stranger_1")
        assert "recent_challenge_passed" not in other.factors
        assert other.should_challenge

        # The actor who passed is still recognised on their own keys.
        again = signup(application, client_id="payer_1")
        assert "recent_challenge_passed" in again.factors

    def test_confirmed_fraud_on_the_actor_voids_the_pass(self, application, no_geoip):
        from core.models import Challenge
        from core.services.network_reputation import NetworkReputation
        from tests.unit.test_challenges import verify
        from tests.unit.test_challenge_replay import signup

        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        first = signup(application, client_id="payer_2")
        challenge = Challenge.objects.get(id=first.challenge["id"])
        verify(challenge, first.challenge["code"])
        NetworkReputation.record(identity_key_ids=challenge.identity_key_ids, application=application, outcome="fraud")

        later = signup(application, client_id="payer_2")
        assert "recent_challenge_passed" not in later.factors

    def test_one_failure_voids_the_pass(self, application, no_geoip):
        from core.models import Challenge
        from core.services.network_reputation import NetworkReputation
        from tests.unit.test_challenges import verify
        from tests.unit.test_challenge_replay import signup

        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        first = signup(application, client_id="payer_3")
        challenge = Challenge.objects.get(id=first.challenge["id"])
        verify(challenge, first.challenge["code"])
        NetworkReputation.record(identity_key_ids=challenge.identity_key_ids, application=application, outcome="challenge_failed")

        assert "recent_challenge_passed" not in signup(application, client_id="payer_3").factors


class TestEvidenceIsLabelled:
    def test_the_ledger_records_where_labels_came_from(self, tmp_path):
        from core.taxonomy import evidence

        path = tmp_path / "evidence.json"
        evidence.record(
            entries=dict(disposable_email_domain=dict(precision=1.0, fired=10), reset_then_login=dict(precision=0.88, fired=26)),
            application="Replay", window=None, path=path, label_source="incident_record",
        )
        ledger = evidence.load(path)
        assert ledger["disposable_email_domain"]["circular"] is True
        assert ledger["reset_then_login"]["circular"] is False
        assert ledger["reset_then_login"]["label_source"] == "incident_record"

        evidence.record(entries=dict(x=dict(precision=1.0)), application="A", window=None, path=path, label_source="nonsense")
        assert evidence.load(path)["x"]["label_source"] == "unknown"

    def test_a_circular_measurement_supports_no_rung(self):
        from core.taxonomy import evidence

        rows = [dict(rule="DisposableRule", maturity="backtested", evidence_codes=["disposable_email_domain"]),
                dict(rule="ResetRule", maturity="backtested", evidence_codes=["reset_then_login"])]
        ledger = dict(
            disposable_email_domain=dict(circular=True, label_source="incident_record"),
            reset_then_login=dict(circular=False, label_source="incident_record"),
        )
        offenders = evidence.unsupported_claims(rows, ledger)
        assert offenders == ["DisposableRule (disposable_email_domain measured against circular labels)"]

    def test_the_shipped_ledger_and_matrix_agree(self):
        """No registered rule claims a rung on a circular measurement, and the matrix says which are."""
        from core.taxonomy import evidence, registry

        assert evidence.unsupported_claims(registry.detectors()) == []
        ledger = evidence.load()
        assert ledger["disposable_email_domain"]["circular"] is True
        assert ledger["reset_then_login"]["circular"] is False
        assert any("block_streak" in line for line in evidence.notes())

    def test_the_figo_mapping_declares_its_label_source(self):
        from core.backtest.mapping import EventMapping
        mapping = EventMapping.load("integrations/figo/events-mapping.json")
        assert mapping.label_source == "incident_record"


class TestTheNetworkCanBeContradicted:
    def test_two_applications_under_one_organization_are_one_witness(self, db):
        from core.models import Application

        alpha = make_application("alpha")
        beta = make_application("beta")
        beta_two = Application.objects.create(name="beta-two", organization=beta.organization)
        key = key_for("ip", SHARED_IP)

        report_fraud(beta, key)
        report_fraud(beta_two, key)
        assert not lookup(alpha, key).is_reportable

        report_fraud(make_application("gamma"), key)
        verdict = lookup(alpha, key)
        assert verdict.is_reportable and verdict.organizations == 2

    def test_legit_reports_and_passed_challenges_offset_the_history(self, db):
        alpha = make_application("alpha")
        witnesses = [make_application(f"w{i}") for i in range(4)]
        key = key_for("ip", SHARED_IP)
        for witness in witnesses:
            report_fraud(witness, key)
        strong = lookup(alpha, key)
        assert strong.is_reportable and strong.organizations == 4

        for witness in witnesses:
            favour(witness, key, "legit", count=5)
            favour(witness, key, "challenge_passed", count=5)
        cleared = lookup(alpha, key)
        assert cleared.net < 0 and not cleared.is_reportable

        # A partial offset weakens it in proportion rather than silencing it.
        strong_device, contradicted_device = key_for("device", "dev_a"), key_for("device", "dev_b")
        for witness in witnesses:
            report_fraud(witness, strong_device, count=3)
            report_fraud(witness, contradicted_device, count=3)
        favour(witnesses[0], contradicted_device, "legit", count=4)
        uncontradicted, partial = lookup(alpha, strong_device), lookup(alpha, contradicted_device)
        assert uncontradicted.severity == 0.85
        assert partial.is_reportable and partial.severity == round(0.85 * 12 / 16, 4)

    def test_failed_challenges_expire_with_the_window(self, db):
        from datetime import timedelta
        from django.utils import timezone
        from core.models.identity import IdentityObservation

        alpha = make_application("alpha")
        key = key_for("ip", SHARED_IP)
        for name in ("beta", "gamma"):
            favour(make_application(name), key, "challenge_failed")
        assert lookup(alpha, key).is_reportable

        IdentityObservation.objects.filter(identity_key=key).update(last_seen_at=timezone.now() - timedelta(days=400))
        assert not lookup(alpha, key).is_reportable

    def test_shared_keys_alone_never_block_but_a_device_does(self, application, no_geoip):
        from core.models.identity import IdentityKey

        # Four organizations confirm fraud on the IP alone.
        ip = "185.199.108.160"
        ip_key = key_for("ip", ip)
        for index in range(4):
            report_fraud(make_application(f"ip{index}"), ip_key)

        on_ip = register(
            application, email="clean.person@gmail.com", ip_address=ip, user_agent=BROWSER,
            visit=make_visit("clean_visitor", ip=ip), visit_id="clean_visitor", client_id="clean_1",
        )
        assert "network_fraud_history" in codes(on_ip)
        assert not on_ip.should_block
        assert on_ip.should_challenge or on_ip.should_review

        # Four organizations confirm fraud on the device: that is the actor.
        device_key = key_for("device", "bad_visitor")
        for index in range(4):
            report_fraud(make_application(f"dev{index}"), device_key)
        on_device = register(
            application, email="another.person@gmail.com", ip_address="185.199.109.10", user_agent=BROWSER,
            visit=make_visit("bad_visitor", ip="185.199.109.10"), visit_id="bad_visitor", client_id="clean_2",
        )
        assert "network_fraud_history" in codes(on_device)
        assert on_device.should_block

    def test_the_verdict_says_what_it_rests_on(self, db):
        alpha = make_application("alpha")
        key = key_for("ip", SHARED_IP)
        for name in ("beta", "gamma"):
            report_fraud(make_application(name), key)
        context = lookup(alpha, key).as_context()
        assert context["key_types"] == ["ip"] and context["shared_only"] is True
        assert context["organizations"] == 2 and context["legit_count"] == 0


class TestTriageSafeguards:
    @pytest.fixture
    def case(self, application, no_geoip):
        from core.models import Case
        result = risky_audit(application, client_id="t_1")
        return Case.objects.get(audit_log_id=result.audit_id)

    def test_the_proposal_is_hidden_while_the_case_is_open(self, case, application):
        from rest_framework.test import APIClient
        from core.auth.actor import Actor

        case.triage_proposal = dict(verdict="cleared", confidence=0.9, reason="r", summary="s", unavailable=False)
        case.save()
        client = APIClient()
        client.force_authenticate(user=None, token=Actor(application))

        row = client.get(f"/api/v1/applications/{application.id}/cases").data["data"]["cases"][0]
        assert row["triage"] is None and row["triage_pending"] is True

        case.resolve(status="confirmed_fraud", assignee=application.organization.owner)
        row = client.get(f"/api/v1/applications/{application.id}/cases?status=all").data["data"]["cases"][0]
        assert row["triage"]["verdict"] == "cleared" and row["triage_pending"] is False

    def test_an_auto_clear_labels_nothing_and_publishes_nothing(self, case, application):
        from unittest.mock import patch
        from core.services.publish_outcome import PublishOutcome

        case.triage_auto_closed = True
        case.save()
        with patch.object(PublishOutcome, "call") as publish:
            case.resolve(status="cleared", note="Auto-cleared by triage: fine")
        case.refresh_from_db()
        case.audit_log.refresh_from_db()
        assert case.status == "cleared" and case.audit_log.label is None
        publish.assert_not_called()

        # A person closing it is what writes the label.
        with patch.object(PublishOutcome, "call") as publish:
            case.resolve(status="cleared", assignee=application.organization.owner)
        case.audit_log.refresh_from_db()
        assert case.audit_log.label == "legit"
        publish.assert_called_once()

    def test_a_chargeback_through_outcomes_trips_the_breaker(self, application, no_geoip):
        from django.core.cache import cache
        from rest_framework.test import APIClient
        from core.auth.actor import Actor
        from core.models import Case
        from core.triage import TriageGuardrails

        cache.clear()
        client = APIClient()
        client.force_authenticate(user=None, token=Actor(application))

        for index in range(3):
            result = risky_audit(application, client_id=f"cb_{index}", id=f"tx_cb_{index}", ip_address=f"45.155.205.{10 + index}")
            case = Case.objects.get(audit_log_id=result.audit_id)
            case.triage_auto_closed = True
            case.save()
            case.resolve(status="cleared")
            response = client.post(
                f"/api/v1/applications/{application.id}/outcomes",
                dict(audit_id=result.audit_id, label="chargeback"), format="json",
            )
            assert response.status_code == 200, response.data

        assert TriageGuardrails.tripped(application) is not None
        allowed, reason = TriageGuardrails.may_auto_clear(application)
        assert not allowed and "circuit breaker" in reason

    def test_a_legit_outcome_ends_the_streak(self, application, no_geoip):
        from django.core.cache import cache
        from core.models import Case
        from core.triage import TriageGuardrails

        cache.clear()
        result = risky_audit(application, client_id="ok_1", id="tx_ok_1")
        case = Case.objects.get(audit_log_id=result.audit_id)
        case.triage_auto_closed = True
        case.save()
        TriageGuardrails.record_override(application, overruled=True)
        TriageGuardrails.record_outcome(application, case.audit_log, "legit")
        _, overrides_key, _ = TriageGuardrails.keys(application.id)
        assert int(cache.get(overrides_key) or 0) == 0

    def test_the_calibrator_ignores_labels_a_model_wrote(self, application, no_geoip):
        from core.calibration.calibrator import Calibrator
        from core.models import Case

        result = risky_audit(application, client_id="cal_1", id="tx_cal_1")
        case = Case.objects.get(audit_log_id=result.audit_id)
        case.triage_auto_closed = True
        case.save()
        # Force the label a pre-fix auto-clear would have written.
        log = case.audit_log
        log.label = "legit"
        log.save(update_fields=["label"])
        assert all(row["decision"].id != log.id for row in Calibrator.load(application, 30))

        case.resolve(status="cleared", assignee=application.organization.owner)
        assert any(row["decision"].id == log.id for row in Calibrator.load(application, 30))

    def test_the_sample_floor_is_a_hundred(self):
        from core.triage import TriageGuardrails
        assert TriageGuardrails.MIN_AGREEMENTS == 100
