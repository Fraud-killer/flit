"""
A rule can run without counting, and be measured.

Shadow at the application level tells a merchant what FLIT would have done.
Shadow at the rule level tells a merchant what one *proposed* rule would have
added: it runs on live traffic, its findings are kept under the decision, and
`shadow_report` measures them against the labels that arrive. That
measurement is what lets the rule claim the shadow-validated rung.
"""

import pytest


def shadow(application, *names):
    policy = application.policy
    policy.shadow_rules = list(names)
    policy.save(update_fields=["shadow_rules"])
    policy.refresh_from_db()


def bot_transfer(application, client_id="bot_1"):
    from tests.unit.test_decision_rules import audit
    from core.audit.events import TransactionEvent

    return audit(application, TransactionEvent(
        id=f"tx_{client_id}", type="debit", amount=10, currency_code="USD",
        client_id=client_id, ip_address="102.91.133.202", user_agent="curl/8.5.0",
    ))


class TestShadowedRules:
    def test_a_shadowed_rules_findings_do_not_count(self, application, no_geoip):
        live = bot_transfer(application, "live")
        assert any(code.startswith("bot_detected") for code in live.factors)

        shadow(application, "BotSignalRule")
        shadowed = bot_transfer(application, "shadowed")

        assert not any(code.startswith("bot_detected") for code in shadowed.factors)
        assert shadowed.risk_score < live.risk_score
        assert "BotSignalRule" in shadowed.rules  # it ran

    def test_but_are_kept_under_the_decision(self, application, no_geoip):
        from core.models import AuditLog

        shadow(application, "BotSignalRule")
        result = bot_transfer(application)

        assert any(f["code"].startswith("bot_detected") for f in result.shadow)
        assert result.shadow[0]["rule"] == "BotSignalRule"

        log = AuditLog.objects.get(id=result.audit_id)
        assert any(f["code"].startswith("bot_detected") for f in log.context["shadow"])

    def test_moving_a_rule_to_shadow_is_a_loosening(self, application):
        from rest_framework.test import APIClient
        from core.auth.actor import Actor

        client = APIClient()
        client.force_authenticate(user=None, token=Actor(application))

        response = client.patch(
            f"/api/v1/applications/{application.id}/policy",
            dict(shadow_rules=["BotSignalRule"]), format="json",
        )

        assert response.status_code == 403


class TestShadowReport:
    def test_the_report_measures_shadow_findings_against_labels(self, application, no_geoip):
        from io import StringIO
        from django.core.management import call_command
        from core.models import AuditLog

        shadow(application, "BotSignalRule")
        fraud = bot_transfer(application, "fraud_1")
        legit = bot_transfer(application, "legit_1")
        AuditLog.objects.filter(id=fraud.audit_id).update(label="fraud")
        AuditLog.objects.filter(id=legit.audit_id).update(label="legit")

        out = StringIO()
        call_command("shadow_report", application=application.name, days=1, json=True, stdout=out)

        import json
        report = json.loads(out.getvalue())
        code = next(c for c in report["codes"] if c.startswith("bot_detected"))
        row = report["codes"][code]
        assert row["rule"] == "BotSignalRule"
        assert row["fired"] == 2
        assert row["on_fraud"] == 1
        assert row["on_legit"] == 1
        assert row["precision"] == 0.5

    def test_recording_evidence_writes_the_ledger(self, application, no_geoip, tmp_path):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command
        from core.models import AuditLog
        from core.taxonomy import evidence

        shadow(application, "BotSignalRule")
        fraud = bot_transfer(application, "fraud_1")
        AuditLog.objects.filter(id=fraud.audit_id).update(label="fraud")

        ledger = tmp_path / "evidence.json"
        with patch.object(evidence, "ledger_path", lambda: ledger):
            call_command(
                "shadow_report", application=application.name, days=1,
                record_evidence=True, stdout=StringIO(),
            )

        recorded = evidence.load(ledger)
        code = next(c for c in recorded if c.startswith("bot_detected"))
        assert recorded[code]["source"] == "shadow"
        assert recorded[code]["application"] == application.name

    def test_no_labels_records_nothing(self, application, no_geoip, tmp_path):
        from io import StringIO
        from unittest.mock import patch
        from django.core.management import call_command
        from core.taxonomy import evidence

        shadow(application, "BotSignalRule")
        bot_transfer(application, "unlabelled")

        ledger = tmp_path / "evidence.json"
        with patch.object(evidence, "ledger_path", lambda: ledger):
            call_command(
                "shadow_report", application=application.name, days=1,
                record_evidence=True, stdout=StringIO(),
            )

        assert not ledger.exists()
