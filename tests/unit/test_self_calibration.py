"""
Tests for the calibrator: the loop that learns from outcomes on its own.

The standard it is held to is the one the rest of FLIT is held to. A weight
moves only when the labelled sample behind the move is big enough to mean
something, only by a bounded step, and only if re-scoring the month under
the new weight blocks no more good customers and catches no less fraud. Every
run is written down whether or not it changed anything, because a held run
with its reason is what a reviewer needs as much as an applied one.
"""

from io import StringIO

from core.scoring import DEFAULT_WEIGHTS

from tests.unit.test_credential_takeover import BROWSER, authenticate, codes


BOT = "bot_detected:http_client"
DATACENTER = "datacenter_ip"
PLUS_TAG = "plus_tagged_email"
VPN = "vpn_detected"


def decide(application, *, factors, label, category="transaction"):
    """One recorded decision with its factors, labelled after the fact."""
    from core.audit.logger import AuditLogger
    from core.audit.models import AuditLog, AuditLogLevel

    stored = [
        dict(code=code, weight=DEFAULT_WEIGHTS.get_weight(code), score=1.0)
        for code in factors
    ]
    log = AuditLogger.log(
        level=AuditLogLevel.INFO, category=category, action="transaction_debit",
        actor_type="client", actor_id=f"client_{label}",
        application_id=application.id,
        risk_factors=list(factors),
        context=dict(factors=stored),
    )
    AuditLog.objects.filter(id=log.id).update(label=label)
    return log


def month_of_outcomes(application):
    """
    A month where one rule earned more say, one earned less, and one has
    not been seen enough to judge.
    """
    for _ in range(38):
        decide(application, factors=[BOT, DATACENTER], label="fraud")
    for _ in range(2):
        decide(application, factors=[PLUS_TAG], label="fraud")
    for _ in range(30):
        decide(application, factors=[DATACENTER], label="legit")
    for _ in range(28):
        decide(application, factors=[PLUS_TAG], label="legit")
    for _ in range(30):
        decide(application, factors=[], label="legit")
    for _ in range(3):
        decide(application, factors=[VPN], label="fraud")


def proposal_for(run, code):
    return next((p for p in run.proposals if p["code"] == code), None)


class TestSampleGate:
    def test_too_few_labels_is_held_and_recorded(self, application):
        from core.calibration import Calibrator
        from core.models import CalibrationRun

        for _ in range(6):
            decide(application, factors=[BOT], label="fraud")
        for _ in range(4):
            decide(application, factors=[], label="legit")

        run = Calibrator.run(application=application, apply=True)

        assert run.mode == "held"
        assert "Too few labels" in run.reason
        assert run.labelled == 10 and run.fraud == 6
        assert run.proposals == []
        assert not run.applied
        assert application.policy.calibration == {}
        assert CalibrationRun.objects.filter(application=application).count() == 1

    def test_a_held_run_still_measures_the_policy_in_force(self, application):
        from core.calibration import Calibrator

        for _ in range(6):
            decide(application, factors=[BOT], label="fraud")

        run = Calibrator.run(application=application)

        # A lone 0.7 factor sits exactly on the block line, so this is what
        # the policy in force does with it: every one caught.
        assert run.before["recall"] == 1.0
        assert run.before["false_positives"] == 0
        assert [point["block_at"] for point in run.threshold_sweep] == [0.6, 0.65, 0.7, 0.75, 0.8]


class TestProposals:
    def test_a_precise_rule_earns_a_bounded_step_up(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        run = Calibrator.run(application=application)

        bot = proposal_for(run, BOT)
        assert bot["direction"] == "up"
        assert bot["from"] == 0.7
        assert bot["to"] == round(0.7 * 1.15, 4)
        assert bot["accepted"], bot["rejected"]
        assert "100%" in bot["reason"]

    def test_a_rule_no_better_than_chance_earns_a_step_down(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        run = Calibrator.run(application=application)

        tag = proposal_for(run, PLUS_TAG)
        assert tag["direction"] == "down"
        assert tag["from"] == 0.1
        assert tag["to"] == round(0.1 * 0.85, 4)
        assert tag["accepted"], tag["rejected"]

    def test_a_rule_without_enough_firings_is_left_alone(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        run = Calibrator.run(application=application)

        assert proposal_for(run, VPN) is None
        # Fires on fraud more than chance but not precisely: no case either way.
        assert proposal_for(run, DATACENTER) is None

    def test_the_month_is_rescored_before_and_after(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        run = Calibrator.run(application=application)

        # Under the defaults the bot-plus-datacenter fraud sat just under the
        # block line. The accepted step takes it over, at no cost in false
        # positives.
        assert run.before["recall"] == 0.0
        assert run.after["recall"] > 0.8
        assert run.after["false_positives"] == 0

    def test_measured_rules_are_named_for_the_reviewer(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        run = Calibrator.run(application=application)

        measured = {row["code"]: row for row in run.measured}
        assert measured[BOT]["precision"] == 1.0
        assert measured[BOT]["eligible_for"] == "production_observed"
        assert VPN not in measured


class TestGuardrails:
    def test_a_step_that_would_block_good_customers_is_rejected(self, application):
        """
        A rule precise enough to earn a step up, whose step would tip the
        good customers it also fires on over the block line.
        """
        from core.calibration import Calibrator

        for _ in range(40):
            decide(application, factors=[BOT, DATACENTER], label="fraud")
        for _ in range(8):
            decide(application, factors=[BOT, DATACENTER], label="legit")
        for _ in range(30):
            decide(application, factors=[], label="legit")

        run = Calibrator.run(application=application, apply=True)

        bot = proposal_for(run, BOT)
        assert bot["direction"] == "up"
        assert not bot["accepted"]
        assert "good customers" in bot["rejected"]

        # Whatever else the run applied, the rejected step never reached
        # the policy, and the good customers are still not blocked.
        application.policy.refresh_from_db()
        assert BOT not in (application.policy.calibration.get("weights") or {})
        assert run.after["false_positives"] == 0

    def test_an_inherited_false_positive_rate_does_not_veto_every_proposal(self, application):
        """
        Figo's first real month: the recomputed baseline already blocked 3.6%
        of good customers because one mule rule fired on 160 of them. Every
        improving proposal was being refused for that inherited number. The
        ceiling binds on what a proposal does, not on what it inherits.
        """
        from core.calibration import Calibrator

        # Good customers already over the line under the weights in force.
        for _ in range(40):
            decide(application, factors=["pass_through_funds", "many_unique_payers"], label="legit")
        for _ in range(60):
            decide(application, factors=[], label="legit")
        # Fraud the precise rule sees and nothing else does.
        for _ in range(40):
            decide(application, factors=[BOT, DATACENTER], label="fraud")

        run = Calibrator.run(application=application)

        assert run.before["false_positive_rate"] > Calibrator.MAX_FALSE_POSITIVE_RATE
        bot = proposal_for(run, BOT)
        assert bot["accepted"], bot["rejected"]
        mule = proposal_for(run, "pass_through_funds")
        assert mule["direction"] == "down" and mule["accepted"], mule["rejected"]
        assert run.after["false_positive_rate"] < run.before["false_positive_rate"]

    def test_a_zero_weight_marker_is_never_proposed(self, application):
        """A code a rule reports at zero weight is information, not evidence."""
        from core.audit.logger import AuditLogger
        from core.audit.models import AuditLog, AuditLogLevel
        from core.calibration import Calibrator

        for label in ["fraud"] * 20 + ["legit"] * 40:
            log = AuditLogger.log(
                level=AuditLogLevel.INFO, category="transaction", action="transaction_debit",
                actor_type="client", actor_id=f"client_{label}", application_id=application.id,
                risk_factors=["policy_currency_mismatch", BOT],
                context=dict(factors=[
                    dict(code="policy_currency_mismatch", weight=0.0, score=0.0),
                    dict(code=BOT, weight=0.7, score=1.0),
                ]),
            )
            AuditLog.objects.filter(id=log.id).update(label=label)

        run = Calibrator.run(application=application)

        assert proposal_for(run, "policy_currency_mismatch") is None

    def test_a_dry_run_changes_nothing(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        run = Calibrator.run(application=application, apply=False)

        assert run.mode == "dry_run"
        assert run.accepted
        assert not run.applied
        application.policy.refresh_from_db()
        assert application.policy.calibration == {}


class TestApply:
    def test_accepted_proposals_are_written_to_the_policy(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        run = Calibrator.run(application=application, apply=True)

        assert run.mode == "applied"
        assert run.applied and run.applied_at is not None

        application.policy.refresh_from_db()
        calibration = application.policy.calibration
        assert calibration["weights"][BOT] == round(0.7 * 1.15, 4)
        assert calibration["weights"][PLUS_TAG] == round(0.1 * 0.85, 4)
        assert calibration["run_id"] == str(run.id)

    def test_the_next_run_steps_from_where_the_last_one_left_off(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        first = Calibrator.run(application=application, apply=True)
        application.policy.refresh_from_db()
        second = Calibrator.run(application=application, apply=True)

        assert proposal_for(first, BOT)["to"] == round(0.7 * 1.15, 4)
        assert proposal_for(second, BOT)["from"] == round(0.7 * 1.15, 4)
        assert proposal_for(second, BOT)["to"] == round(round(0.7 * 1.15, 4) * 1.15, 4)

    def test_a_weight_never_leaves_its_bounds(self, application):
        from core.calibration import Calibrator

        month_of_outcomes(application)
        for _ in range(12):
            Calibrator.run(application=application, apply=True)
            application.policy.refresh_from_db()

        weights = application.policy.calibration["weights"]
        assert weights[BOT] <= Calibrator.CEILING
        assert weights[PLUS_TAG] >= Calibrator.FLOOR

    def test_decisions_use_what_was_learned(self, application, second_application, no_geoip):
        """
        The policy a simulation predicted is the policy that decides.
        """
        from core.audit.events import AuthenticationEvent

        application.policy.calibration = dict(weights={DATACENTER: 1.0})
        application.policy.save()

        calibrated = authenticate(
            application, client_id="traveller", action=AuthenticationEvent.LOGIN,
            ip_address="35.240.149.171", user_agent=BROWSER,
        )
        default = authenticate(
            second_application, client_id="traveller", action=AuthenticationEvent.LOGIN,
            ip_address="35.240.149.171", user_agent=BROWSER,
        )

        assert codes(calibrated) == codes(default) == {DATACENTER}
        assert calibrated.risk_score > default.risk_score
        assert calibrated.should_block and not default.should_block


class TestCommand:
    def test_the_nightly_command_reports_every_application(self, application, second_application):
        from django.core.management import call_command

        month_of_outcomes(application)
        out = StringIO()
        call_command("calibrate", "--all", stdout=out)
        report = out.getvalue()

        assert "Test App: dry_run" in report
        assert "Other App: held" in report
        assert BOT in report
        assert "accepted" in report

    def test_apply_from_the_command_writes_the_policy(self, application):
        from django.core.management import call_command

        month_of_outcomes(application)
        call_command("calibrate", "--application", "Test App", "--apply", stdout=StringIO())

        application.policy.refresh_from_db()
        assert BOT in application.policy.calibration["weights"]
