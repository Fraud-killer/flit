"""
A playbook earns auto mode by agreeing with people.
"""

from core.agent.evals import PlaybookEval
from core.models import AgentPolicy, CaseStatus
from tests.unit.agent_fakes import FakeModel, report, agent_on, open_case


class TestEvaluation:
    def test_agreement_is_measured_and_stored(self, application, no_geoip):
        owner = application.organization.owner
        fraud = open_case(application, client_id="e1", id="e1")
        fraud.resolve(status=CaseStatus.CONFIRMED_FRAUD, assignee=owner)
        legit = open_case(application, client_id="e2", id="e2")
        legit.resolve(status=CaseStatus.CLEARED, assignee=owner)

        # The model says fraud for both: one agreement, one disagreement.
        model = FakeModel(turns=[[report("confirmed_fraud")], [report("confirmed_fraud")]])
        with agent_on():
            result = PlaybookEval.run(application=application, playbook="investigate_case", size=10, client=model)

        assert result["n"] == 2 and result["decided"] == 2
        assert result["agreed"] == 1 and result["disagreed"] == 1 and result["agreement"] == 0.5
        policy = AgentPolicy.for_application(application)
        assert policy.evaluations["investigate_case"]["agreement"] == 0.5
        assert PlaybookEval.may_run_unattended(policy, "investigate_case") is False

    def test_the_gate(self):
        class P:
            evaluations = {"ok": dict(agreement=0.95, decided=25), "thin": dict(agreement=1.0, decided=3), "bad": dict(agreement=0.8, decided=50)}
        assert PlaybookEval.may_run_unattended(P, "ok")
        assert not PlaybookEval.may_run_unattended(P, "thin")
        assert not PlaybookEval.may_run_unattended(P, "bad")
        assert not PlaybookEval.may_run_unattended(P, "never")
        assert PlaybookEval.ceiling(P, "thin", "auto") == "ask"
        assert PlaybookEval.ceiling(P, "ok", "auto") == "auto"
        assert PlaybookEval.ceiling(P, "never", "propose") == "propose"
