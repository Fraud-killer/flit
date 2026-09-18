"""
Tests for the decision console: the case queue, the decision feed, labels
from review, and policy simulation over recorded decisions.
"""

import asyncio


def transaction(**attributes):
    from core.audit.events import TransactionEvent

    attributes.setdefault("id", "tx_1")
    attributes.setdefault("type", "debit")
    attributes.setdefault("amount", 25)
    attributes.setdefault("currency_code", "NGN")
    attributes.setdefault("client_id", "user_1")
    return TransactionEvent(**attributes)


def audit(application, **attributes):
    from core.audit.auditor import Auditor

    return asyncio.run(
        Auditor.audit(transaction(**attributes), application.policy, send_alerts=False)
    )


def risky_audit(application, **attributes):
    """A decision that scores high enough to be reviewed."""
    attributes.setdefault("user_agent", "curl/8.0")
    attributes.setdefault("ip_address", "45.155.205.77")
    return audit(application, **attributes)


def client_for(application):
    from rest_framework.test import APIClient
    from core.auth.actor import Actor

    client = APIClient()
    client.force_authenticate(user=None, token=Actor(application))
    return client


class TestDecisionThresholds:
    def test_defaults_match_the_previous_behaviour(self):
        from core.scoring import RiskEngine

        engine = RiskEngine()

        assert engine.thresholds.block_at == 0.7
        assert engine.thresholds.review_at == 0.5

    def test_thresholds_decide_the_action(self):
        from core.scoring import RiskEngine, RiskThresholds

        messages = [dict(code="account_takeover_risk", text="", context={})]

        strict = RiskEngine(thresholds=RiskThresholds(block_at=0.1, review_at=0.05))
        lenient = RiskEngine(thresholds=RiskThresholds(block_at=0.99, review_at=0.98))

        assert strict.calculate_risk(messages).should_block
        assert not lenient.calculate_risk(messages).should_block
        assert not lenient.calculate_risk(messages).should_review


class TestCaseQueue:
    def test_a_reviewable_decision_opens_a_case(self, application, no_geoip):
        from core.models import Case

        result = risky_audit(application)

        assert result.should_review
        case = Case.objects.get(audit_log_id=result.audit_id)
        assert case.status == "open"
        assert case.application_id == application.id

    def test_a_low_risk_decision_opens_no_case(self, application, no_geoip):
        from core.models import Case

        result = audit(application)

        assert not result.should_review
        assert Case.objects.count() == 0

    def test_resolving_a_case_labels_the_decision(self, application, no_geoip):
        from core.models import Case, AuditLog

        result = risky_audit(application)
        case = Case.objects.get(audit_log_id=result.audit_id)

        case.resolve(status="confirmed_fraud", note="Card reported stolen")

        case.refresh_from_db()
        assert case.closed_at is not None
        assert case.resolution_note == "Card reported stolen"

        audit_log = AuditLog.objects.get(id=result.audit_id)
        assert audit_log.label == "fraud"
        assert audit_log.labeled_at is not None

    def test_clearing_a_case_labels_it_legitimate(self, application, no_geoip):
        from core.models import Case, AuditLog

        result = risky_audit(application)
        Case.objects.get(audit_log_id=result.audit_id).resolve(status="cleared")

        assert AuditLog.objects.get(id=result.audit_id).label == "legit"

    def test_a_failing_case_does_not_fail_the_decision(self, application, no_geoip, monkeypatch):
        from core.audit.recorder import AuditRecorder

        def explode(*args, **kwargs):
            raise RuntimeError("cases table is gone")

        monkeypatch.setattr(AuditRecorder, "open_case", explode)

        result = risky_audit(application)

        # The audit still returns a decision; only the case was lost.
        assert result.risk_level
        assert result.audit_id is None


class TestConsoleEndpoints:
    def test_decision_feed_lists_and_summarises(self, application, no_geoip):
        risky_audit(application, id="tx_risky")
        audit(application, id="tx_clean")

        response = client_for(application).get(f"/api/v1/applications/{application.id}/decisions")

        assert response.status_code == 200, response.data
        data = response.data["data"]
        assert data["total"] == 2
        assert data["summary"]["open_cases"] == 1

        risky = next(d for d in data["decisions"] if d["event_id"] == "tx_risky")
        assert risky["case"]["status"] == "open"
        assert "bot_detected:http_client" in risky["factors"]

    def test_decision_feed_filters(self, application, no_geoip):
        risky_audit(application, id="tx_risky")
        audit(application, id="tx_clean", client_id="user_2")

        client = client_for(application)
        url = f"/api/v1/applications/{application.id}/decisions"

        by_client = client.get(url, dict(client_id="user_2")).data["data"]
        assert [d["event_id"] for d in by_client["decisions"]] == ["tx_clean"]

        by_factor = client.get(url, dict(factor="bot_detected:http_client")).data["data"]
        assert [d["event_id"] for d in by_factor["decisions"]] == ["tx_risky"]

        unlabelled = client.get(url, dict(unlabelled="1")).data["data"]
        assert unlabelled["total"] == 2

    def test_decision_feed_rejects_bad_filters(self, application):
        response = client_for(application).get(
            f"/api/v1/applications/{application.id}/decisions", dict(level="disastrous")
        )

        assert response.status_code == 400
        assert [error["code"] for error in response.data["errors"]] == ["in_choices"]

    def test_case_queue_and_resolution(self, application, no_geoip):
        from core.models import AuditLog, CaseNote

        risky_audit(application)
        client = client_for(application)

        queue = client.get(f"/api/v1/applications/{application.id}/cases").data["data"]
        assert queue["total"] == 1
        case = queue["cases"][0]
        assert case["status"] == "open"
        assert case["risk_level"]

        response = client.patch(
            f"/api/v1/applications/{application.id}/cases/{case['id']}",
            dict(status="confirmed_fraud", note="Mule account"),
            format="json",
        )

        assert response.status_code == 200, response.data
        assert response.data["data"]["case"]["status"] == "confirmed_fraud"
        assert response.data["data"]["case"]["label"] == "fraud"

        assert AuditLog.objects.get(id=case["audit_id"]).label == "fraud"
        assert CaseNote.objects.get().body == "Mule account"

        # Resolved cases leave the open queue.
        assert client.get(f"/api/v1/applications/{application.id}/cases").data["data"]["total"] == 0

    def test_case_of_another_application_is_not_reachable(self, application, second_application, no_geoip):
        from core.models import Case

        risky_audit(application)
        case = Case.objects.get()

        response = client_for(second_application).patch(
            f"/api/v1/applications/{second_application.id}/cases/{case.id}",
            dict(status="cleared"),
            format="json",
        )

        assert response.status_code == 400
        assert [error["code"] for error in response.data["errors"]] == ["case_ref_exist"]

    def test_console_endpoints_require_authentication(self, application):
        from rest_framework.test import APIClient

        response = APIClient().get(f"/api/v1/applications/{application.id}/decisions")

        assert response.status_code == 401


class TestSimulation:
    def labelled_history(self, application):
        """Two frauds that scored high, one legitimate payment that did not."""
        from core.models import Case, AuditLog

        for index in (1, 2):
            result = risky_audit(application, id=f"tx_fraud_{index}", client_id=f"fraudster_{index}")
            Case.objects.get(audit_log_id=result.audit_id).resolve(status="confirmed_fraud")

        clean = audit(application, id="tx_good", client_id="good_customer")
        AuditLog.objects.filter(id=clean.audit_id).update(label="legit")

        return clean

    def simulate(self, application, **body):
        return client_for(application).post(
            f"/api/v1/applications/{application.id}/simulations", body, format="json",
        )

    def test_baseline_reports_what_the_current_policy_does(self, application, no_geoip):
        self.labelled_history(application)

        data = self.simulate(application).data["data"]

        assert data["decisions"] == 3
        assert data["labelled"] == 3
        assert data["approximated_decisions"] == 0
        assert data["baseline"] == data["candidate"]
        assert data["changes"]["newly_blocked"] == 0
        assert data["changes"]["newly_allowed"] == 0

    def test_baseline_reports_the_fraud_the_current_policy_catches(self, application, no_geoip):
        self.labelled_history(application)

        data = self.simulate(application).data["data"]

        # Both frauds score above the 0.7 block threshold; the good payment
        # scores 0.0, so the current policy already separates them.
        assert data["baseline"]["caught_fraud"] == 2
        assert data["baseline"]["false_positives"] == 0
        assert data["baseline"]["precision"] == 1.0
        assert data["baseline"]["recall"] == 1.0

    def test_a_reckless_threshold_shows_the_false_positives(self, application, no_geoip):
        self.labelled_history(application)

        data = self.simulate(application, thresholds=dict(block_at=0.0)).data["data"]

        # Blocking everything catches all the fraud and every good customer
        # with it, which is exactly what precision is meant to expose.
        assert data["candidate"]["blocked"] == 3
        assert data["candidate"]["false_positives"] == 1
        assert data["candidate"]["recall"] == 1.0
        assert data["candidate"]["precision"] == round(2 / 3, 4)
        assert data["changes"]["newly_blocked_legit"] == 1

    def test_a_looser_threshold_lets_fraud_through(self, application, no_geoip):
        self.labelled_history(application)

        data = self.simulate(application, thresholds=dict(block_at=0.99)).data["data"]

        assert data["candidate"]["blocked"] == 0
        assert data["candidate"]["caught_fraud"] == 0
        assert data["candidate"]["missed_fraud"] == 2

    def test_a_candidate_weight_changes_the_outcome(self, application, no_geoip):
        self.labelled_history(application)

        # The default bot weight (0.7) blocks both frauds.
        default_weight = self.simulate(application, thresholds=dict(block_at=0.3)).data["data"]
        assert default_weight["candidate"]["blocked"] == 2

        # Trusting bot detection less lets them through, at the same threshold.
        lowered = self.simulate(
            application,
            weights={"bot_detected": 0.05},
            thresholds=dict(block_at=0.3),
        ).data["data"]

        assert lowered["candidate"]["blocked"] == 0
        assert lowered["candidate"]["missed_fraud"] == 2
        assert lowered["thresholds"]["block_at"] == 0.3

    def test_an_override_reaches_codes_without_a_named_weight(self, application, no_geoip):
        self.labelled_history(application)

        # `bot_detected:http_client` has no field of its own; it resolves
        # through the code prefix, and an override must still win.
        data = self.simulate(
            application,
            weights={"bot_detected:http_client": 0.1},
        ).data["data"]

        assert data["baseline"]["blocked"] == 2
        assert data["candidate"]["blocked"] == 0
        assert data["changes"]["newly_allowed_fraud"] == 2

    def test_rejects_nonsense_input(self, application):
        assert self.simulate(application, weights={"bot_detected": 7}).status_code == 400
        assert self.simulate(application, thresholds=dict(block_at="high")).status_code == 400
        assert self.simulate(application, days=9999).status_code == 400

    def test_older_decisions_without_factor_detail_are_marked_approximate(self, application, no_geoip):
        from core.models import AuditLog

        result = risky_audit(application)

        # Simulate a row recorded before factor detail was kept.
        audit_log = AuditLog.objects.get(id=result.audit_id)
        context = audit_log.context
        context.pop("factors")
        AuditLog.objects.filter(id=audit_log.id).update(context=context)

        data = self.simulate(application).data["data"]

        assert data["approximated_decisions"] == 1
        assert data["decisions"] == 1
