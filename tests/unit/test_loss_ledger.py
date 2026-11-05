"""
Money is the unit a decision is judged by.

A label says what happened; the amount says what it cost. These tests hold
FLIT to adding that up honestly: a reported loss wins over the transaction's
amount, a row with no amount is counted and never guessed, currencies are
never mixed, and a weight change that would lose more money is refused even
when every count looks the same.
"""

from decimal import Decimal

import pytest

from core.scoring import DEFAULT_WEIGHTS


BOT = "bot_detected:http_client"
DATACENTER = "datacenter_ip"


def decide(application, *, factors=(), label=None, amount=None, currency="USD",
           should_block=False, should_review=False, enforcement="enforcing",
           loss_amount=None, loss_currency=None):
    from core.audit.logger import AuditLogger
    from core.audit.models import AuditLog, AuditLogLevel

    stored = [dict(code=code, weight=DEFAULT_WEIGHTS.get_weight(code), score=1.0) for code in factors]
    context = dict(factors=stored, should_block=should_block, should_review=should_review,
                   enforcement=enforcement)
    if amount is not None:
        context.update(amount=amount, currency_code=currency)

    log = AuditLogger.log(
        level=AuditLogLevel.INFO, category="transaction", action="transaction_debit",
        actor_type="client", actor_id="client_1",
        application_id=application.id,
        risk_factors=list(factors),
        context=context,
    )
    AuditLog.objects.filter(id=log.id).update(
        label=label, loss_amount=loss_amount, loss_currency=loss_currency,
    )
    return AuditLog.objects.get(id=log.id)


def app_client(application):
    from rest_framework.test import APIClient
    from core.auth.actor import Actor

    client = APIClient()
    client.force_authenticate(user=None, token=Actor(application))
    return client


@pytest.fixture
def usd_application(application):
    application.policy.aml_cft_limit = "USD 10,000.00"
    application.policy.save()
    return application


class TestMoneyAtStake:
    def test_the_transaction_amount_stands_in_when_nothing_was_reported(self, application):
        from core.loss import Loss

        decision = decide(application, amount=250, label="fraud")
        assert Loss.at_stake(decision) == (Decimal("250.00"), "USD")

    def test_a_reported_loss_wins_over_the_transaction_amount(self, application):
        from core.loss import Loss

        decision = decide(application, amount=250, label="fraud",
                          loss_amount=Decimal("40.00"), loss_currency="USD")
        assert Loss.at_stake(decision) == (Decimal("40.00"), "USD")

    def test_a_decision_with_no_amount_is_unpriced_not_zero(self, application):
        from core.loss import Loss

        decision = decide(application, label="fraud")
        assert Loss.at_stake(decision) == (None, None)

    def test_the_application_currency_is_the_limit_currency(self, usd_application):
        from core.loss import Loss

        assert Loss.currency_of(usd_application.policy) == "USD"

    @pytest.mark.parametrize("value", ["-1", "abc", True, float("nan")])
    def test_amounts_that_are_not_money_are_refused(self, value):
        from core.loss import to_amount

        assert to_amount(value) is None


class TestLossReport:
    def test_fraud_and_friction_land_in_their_buckets(self, usd_application):
        from core.loss import LossReport

        decide(usd_application, amount=1000, label="fraud", should_block=True)
        decide(usd_application, amount=500, label="chargeback", should_block=False)
        decide(usd_application, amount=200, label="fraud", should_review=True)
        decide(usd_application, amount=75, label="legit", should_block=True)
        decide(usd_application, amount=9999, label="legit", should_block=False)
        decide(usd_application, amount=300, label="fraud", should_block=True, enforcement="shadow")

        report = LossReport.call(application=usd_application, days=30)
        usd = report["money"]["USD"]

        assert usd["prevented"] == 1000.0
        assert usd["in_shadow"] == 300.0
        assert usd["flagged"] == 200.0
        assert usd["leaked"] == 500.0
        assert usd["friction"] == 75.0
        assert usd["net"] == 925.0
        assert usd["leak_rate"] == 0.25
        assert report["counts"]["unpriced"] == 0
        assert report["counts"]["legit"] == 2

    def test_currencies_are_never_added_together(self, usd_application):
        from core.loss import LossReport

        decide(usd_application, amount=100, label="fraud", should_block=True)
        decide(usd_application, amount=100, label="fraud", should_block=True, currency="NGN")

        report = LossReport.call(application=usd_application, days=30)

        assert report["money"]["USD"]["prevented"] == 100.0
        assert report["money"]["NGN"]["prevented"] == 100.0
        assert set(report["money"]) == {"USD", "NGN"}

    def test_unpriced_rows_are_counted_and_said_so(self, usd_application):
        from core.loss import LossReport

        decide(usd_application, label="fraud", should_block=False)
        decide(usd_application, amount=50, label="fraud", should_block=False)

        report = LossReport.call(application=usd_application, days=30)

        assert report["counts"]["leaked"] == 2
        assert report["counts"]["unpriced"] == 1
        assert report["money"]["USD"]["leaked"] == 50.0
        assert "1 without an amount" in LossReport.render(report)

    def test_a_report_with_no_amounts_says_so_rather_than_showing_zeros(self, usd_application):
        from core.loss import LossReport

        decide(usd_application, label="fraud", should_block=True)
        report = LossReport.call(application=usd_application, days=30)

        assert report["money"] == {}
        assert "nothing to add up" in LossReport.render(report)


class TestReportingAnOutcomeWithMoney:
    def url(self, application):
        return f"/api/v1/applications/{application.id}/outcomes"

    def test_the_label_defaults_to_the_transaction_amount(self, application):
        decision = decide(application, amount=120.5)

        response = app_client(application).post(
            self.url(application), dict(audit_id=str(decision.id), label="fraud"), format="json",
        )

        assert response.status_code == 200, response.data
        assert response.data["data"]["amount"] == 120.5
        assert response.data["data"]["currency_code"] == "USD"
        decision.refresh_from_db()
        assert decision.loss_amount == Decimal("120.50")

    def test_a_reported_amount_is_stored_as_the_loss(self, application):
        decision = decide(application, amount=120.5)

        response = app_client(application).post(
            self.url(application),
            dict(audit_id=str(decision.id), label="chargeback", amount="80.00", currency_code="USD"),
            format="json",
        )

        assert response.status_code == 200, response.data
        decision.refresh_from_db()
        assert decision.loss_amount == Decimal("80.00")
        assert decision.loss_currency == "USD"

    def test_an_amount_needs_a_currency_and_must_be_money(self, application):
        decision = decide(application, amount=120.5)
        client = app_client(application)

        without_currency = client.post(
            self.url(application), dict(audit_id=str(decision.id), label="fraud", amount=10), format="json",
        )
        negative = client.post(
            self.url(application),
            dict(audit_id=str(decision.id), label="fraud", amount=-10, currency_code="USD"), format="json",
        )
        bad_currency = client.post(
            self.url(application),
            dict(audit_id=str(decision.id), label="fraud", amount=10, currency_code="dollars"), format="json",
        )

        assert without_currency.status_code == 400
        assert negative.status_code == 400
        assert bad_currency.status_code == 400
        decision.refresh_from_db()
        assert decision.label is None

    def test_the_ledger_is_readable_from_the_api(self, usd_application):
        decide(usd_application, amount=1000, label="fraud", should_block=True)
        decide(usd_application, amount=10, label="legit", should_block=True)

        response = app_client(usd_application).get(
            f"/api/v1/applications/{usd_application.id}/loss?days=7"
        )

        assert response.status_code == 200, response.data
        data = response.data["data"]
        assert data["window"]["days"] == 7
        assert data["money"]["USD"]["net"] == 990.0

    def test_the_management_command_prints_the_same_ledger(self, usd_application):
        from io import StringIO
        from django.core.management import call_command

        decide(usd_application, amount=1000, label="fraud", should_block=True)
        out = StringIO()
        call_command("loss_report", application=usd_application.name, stdout=out)

        assert "prevented" in out.getvalue()
        assert "1,000.00" in out.getvalue()


class TestCalibratorMoney:
    def rows(self, decisions):
        from core.services.simulate_policy import SimulatePolicy

        return [dict(decision=d, factors=SimulatePolicy.factors_for(d)[0]) for d in decisions]

    def test_measure_adds_up_the_money_behind_the_counts(self, usd_application):
        from core.calibration import Calibrator
        from core.calibration.engine import engine_for

        caught = decide(usd_application, factors=[BOT, DATACENTER], amount=5000, label="fraud")
        missed = decide(usd_application, factors=[], amount=700, label="fraud")
        turned_away = decide(usd_application, factors=[BOT, DATACENTER], amount=30, label="legit")
        foreign = decide(usd_application, factors=[], amount=100, label="fraud", currency="NGN")

        # The default engine scores bot + datacenter at 0.65 for a transaction;
        # a block line just under it makes the arithmetic the thing under test.
        measured = Calibrator.measure(
            engine_for(usd_application.policy), self.rows([caught, missed, turned_away, foreign]),
            block_at=0.6, currency="USD",
        )

        assert measured["caught_fraud"] == 1
        assert measured["caught_amount"] == 5000.0
        assert measured["missed_amount"] == 700.0
        assert measured["false_positive_amount"] == 30.0
        assert measured["loss"] == 730.0
        assert measured["unpriced"] == 1
        assert measured["currency"] == "USD"

    def test_a_change_that_loses_more_money_fails_the_guardrail_on_equal_counts(self):
        from core.calibration import Calibrator

        before = dict(false_positive_rate=0.005, recall=0.9, loss=1000.0, currency="USD")
        same_counts_more_money = dict(false_positive_rate=0.005, recall=0.9, loss=25000.0, currency="USD")
        less_money = dict(false_positive_rate=0.005, recall=0.9, loss=400.0, currency="USD")

        refused = Calibrator.guardrail(before, same_counts_more_money)
        assert refused is not None
        assert "USD 1,000.00 to USD 25,000.00" in refused
        assert Calibrator.guardrail(before, less_money) is None

    def test_without_priced_rows_the_loss_guardrail_stays_out_of_the_way(self):
        from core.calibration import Calibrator

        before = dict(false_positive_rate=0.005, recall=0.9, loss=None, currency="USD")
        after = dict(false_positive_rate=0.005, recall=0.9, loss=None, currency="USD")

        assert Calibrator.guardrail(before, after) is None

    def test_the_run_report_names_the_money(self, usd_application):
        from core.calibration import Calibrator, format_run

        for _ in range(3):
            decide(usd_application, factors=[BOT], amount=100, label="fraud")
        run = Calibrator.run(application=usd_application)

        assert run.before["currency"] == "USD"
        assert run.before["loss"] == 300.0 or run.before["caught_amount"] == 300.0
        assert "USD lost or turned away" in format_run(run)


class TestShadowReportMoney:
    def test_each_shadow_code_reports_the_money_it_fired_on(self, usd_application):
        from core.management.commands.shadow_report import Command

        rows = [
            dict(label="fraud", risk_score=0.3, loss_amount=None, loss_currency=None,
                 context=dict(amount=900, currency_code="USD", should_block=False,
                              shadow=[dict(rule="NewRule", code="new_signal")])),
            dict(label="legit", risk_score=0.1, loss_amount=Decimal("15.00"), loss_currency="USD",
                 context=dict(amount=15, currency_code="USD", should_block=False,
                              shadow=[dict(rule="NewRule", code="new_signal")])),
            dict(label="fraud", risk_score=0.3, loss_amount=None, loss_currency=None,
                 context=dict(amount=100, currency_code="NGN", should_block=False,
                              shadow=[dict(rule="NewRule", code="new_signal")])),
        ]

        report = Command.measure(rows, usd_application, 14)
        code = report["codes"]["new_signal"]

        assert code["fired"] == 3
        assert code["fraud_amount"] == 900.0
        assert code["legit_amount"] == 15.0
        assert report["money"] == dict(currency="USD", unpriced=1)
        assert "fraud money" in Command.render(report)
