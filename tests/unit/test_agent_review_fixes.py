"""
Guardrails that a review found were not holding, now held.

Each test here is a defect the first review of Agent FLIT turned up: a
breaker that never tripped, a hook that could widen a write or turn a
proposal into something a person could execute, an evaluation that let the
model read the answer, a budget that counted one call in five, evidence lost
when a run resumed, a monitor watching the wrong device id, the agent graded
against its own closures, and a confirmed memory the agent could overwrite.
"""

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.utils import timezone

from core.models import AgentPolicy, AgentMode, InvestigationStatus, StepStatus, CaseStatus
from tests.unit.agent_fakes import FakeModel, report, finding, agent_on, open_case, run


@pytest.fixture
def case(application, no_geoip):
    return open_case(application)


def policy_for(application, **fields):
    policy = AgentPolicy.for_application(application)
    for key, value in fields.items():
        setattr(policy, key, value)
    policy.save()
    return policy


def hooked(answer):
    from core.agent.hooks import AgentHooks
    return patch.object(AgentHooks, "call", classmethod(lambda cls, policy, body, timeout_ms=None: answer))


class TestTheBreakerCountsRejections:
    def test_a_person_rejecting_an_unattended_write_is_counted(self, application, case):
        from core.agent import Investigations, AgentGuardrails

        policy_for(application, mode=AgentMode.ASK, allow=["case_resolve"])
        # The verifier holds the write, so the step is the agent's own judgement awaiting a person.
        model = FakeModel(
            turns=[[("tool", "case_resolve", dict(case_id=str(case.id), status="cleared", note="looks fine"))], [report("needs_human")]],
            structured={"verify one finding": dict(verdict="plausible", reason="thin", missing=[])},
        )
        with agent_on():
            investigation = run(application, model=model, case=case)
            step = investigation.steps.get(tool="case_resolve")
            assert step.status == StepStatus.PENDING and step.decision_source == "verifier"
            with patch.object(AgentGuardrails, "record_review", classmethod(lambda cls, app, rejected: calls.append(rejected))) as _:
                calls = []
                Investigations.answer(step, user=application.organization.owner, note="no", approved=False, client=model, resume=True)

        assert calls == [True]


class TestTheHookCannotLoosen:
    def test_ask_does_not_turn_a_proposal_into_an_executable_approval(self, application, case):
        policy_for(application, mode=AgentMode.PROPOSE, hook_url="https://controls.bank.example/agent")
        model = FakeModel(turns=[[("tool", "case_note", dict(case_id=str(case.id), body="n"))], [report("no_action")]])
        with agent_on(), hooked((200, dict(decision="ask", reason="let a person see it"), None)):
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="case_note")
        assert step.status == StepStatus.PROPOSED
        assert step.hook["outcome"] == "propose"

    def test_deny_still_stops_a_proposal(self, application, case):
        policy_for(application, mode=AgentMode.PROPOSE, hook_url="https://controls.bank.example/agent")
        model = FakeModel(turns=[[("tool", "case_note", dict(case_id=str(case.id), body="n"))], [report("no_action")]])
        with agent_on(), hooked((200, dict(decision="deny", reason="freeze"), None)):
            investigation = run(application, model=model, case=case)
        assert investigation.steps.get(tool="case_note").status == StepStatus.DENIED

    def test_a_rewritten_input_goes_back_through_the_rules(self, application, case):
        policy_for(application, mode=AgentMode.ASK, allow=["block_actor(ip:*)"], deny=["block_actor(country:*)"],
                   hook_url="https://controls.bank.example/agent")
        proposed = dict(subject="ip", pattern="45.155.205.77", reason="probe", expires_hours=4)
        widened = dict(subject="country", pattern="NG", reason="probe", expires_hours=4)
        model = FakeModel(turns=[[("tool", "block_actor", proposed)], [report("no_action")]])
        with agent_on(), hooked((200, dict(decision="allow", updated_input=widened), None)):
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="block_actor")
        assert step.status == StepStatus.DENIED
        assert step.subject == "country:NG"
        application.policy.refresh_from_db()
        assert not any(rule.get("subject") == "country" for rule in (application.policy.rules or {}).get("block", []))


class TestEvaluationHidesTheAnswer:
    def test_case_read_shows_an_open_case_with_no_labels_during_evaluation(self, application, no_geoip):
        from core.agent.evals import PlaybookEval

        owner = application.organization.owner
        closed = open_case(application, client_id="e1", id="e1")
        closed.resolve(status=CaseStatus.CONFIRMED_FRAUD, assignee=owner)
        closed.audit_log.label = "fraud"
        closed.audit_log.save(update_fields=["label"])

        model = FakeModel(turns=[
            [("tool", "case_read", dict(case_id=str(closed.id))), ("tool", "describe_account", dict(client_id="e1"))],
            [report("confirmed_fraud")],
        ])
        with agent_on():
            PlaybookEval.run(application=application, playbook="investigate_case", size=10, client=model)

        results = model.tool_results()
        case_view = results[0]
        assert case_view["status"] == "open" and case_view["closed_at"] is None
        assert "label" not in case_view["decisions"][0]
        assert "labels" not in results[1]
        assert "fraud" not in str(results)

    def test_a_normal_run_still_sees_the_case_as_it_is(self, application, no_geoip):
        owner = application.organization.owner
        closed = open_case(application, client_id="e2", id="e2")
        closed.resolve(status=CaseStatus.CLEARED, assignee=owner)
        model = FakeModel(turns=[[("tool", "case_read", dict(case_id=str(closed.id)))], [report("no_action")]])
        with agent_on():
            run(application, model=model, case=closed)
        assert model.tool_results()[0]["status"] == "cleared"

    def test_cases_the_agent_closed_are_not_in_the_sample(self, application, no_geoip):
        from core.agent.evals import PlaybookEval

        owner = application.organization.owner
        by_person = open_case(application, client_id="p1", id="p1")
        by_person.resolve(status=CaseStatus.CLEARED, assignee=owner)

        by_agent = open_case(application, client_id="a1", id="a1")
        policy_for(application, mode=AgentMode.ASK, allow=["case_resolve"])
        model = FakeModel(turns=[
            [("tool", "case_resolve", dict(case_id=str(by_agent.id), status="confirmed_fraud", note="mule"))],
            [report("confirmed_fraud")],
        ])
        with agent_on():
            run(application, model=model, case=by_agent)
        by_agent.refresh_from_db()
        assert by_agent.status == CaseStatus.CONFIRMED_FRAUD

        sample = PlaybookEval.sample(application, 10)
        assert [c.id for c in sample] == [by_person.id]


class TestEveryCallIsMetered:
    def test_verifier_and_classifier_calls_count_toward_the_budget(self, application, case):
        policy_for(application, mode=AgentMode.ASK)
        model = FakeModel(turns=[
            [("tool", "case_read", dict(case_id=str(case.id)))],
            [report("needs_human", findings=[finding(tool="case_read"), finding(tool="case_read", title="Another")])],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
        # Two main turns plus two verifier calls, every one of them in the run's usage.
        assert len(model.requests) == 4
        assert investigation.usage["requests"] == 4
        assert investigation.cost_usd == pytest.approx(4 * (1000 * 4.0 + 200 * 20.0 + 800 * 0.20) / 1_000_000)


class TestEvidenceSurvivesAResume:
    def test_findings_cite_outputs_from_before_the_pause(self, application, case):
        from core.agent import Investigations

        policy_for(application, mode=AgentMode.ASK)
        model = FakeModel(turns=[
            [("tool", "case_read", dict(case_id=str(case.id)))],
            [("tool", "case_note", dict(case_id=str(case.id), body="checked"))],
            [report("needs_human", findings=[finding(tool="case_read")])],
        ])
        verifier_saw = []

        def verifier(kwargs):
            verifier_saw.append(kwargs["messages"][0]["content"])
            return dict(verdict="confirmed", reason="borne out", missing=[])

        model.structured = {"verify one finding": verifier}
        with agent_on():
            investigation = run(application, model=model, case=case)
            step = investigation.steps.get(tool="case_note")
            assert step.status == StepStatus.PENDING
            # A different worker picks the run up: a fresh runner, no in-memory outputs.
            investigation = Investigations.answer(step, user=application.organization.owner, approved=True, client=model, resume=True)

        assert investigation.status == InvestigationStatus.COMPLETED
        verification = investigation.report["findings"][0]["verification"]
        assert verification["verdict"] == "confirmed"
        assert verifier_saw and '"case_read"' in verifier_saw[0]


class TestMonitorsWatchTheDeviceTheyMean:
    def test_a_device_identity_id_is_translated_to_its_fingerprint(self, application):
        from core.agent import Monitors
        from core.models import DeviceIdentity

        device = DeviceIdentity.objects.create(source="fingerprint", external_id="visitor_99")
        assert Monitors.fingerprint(str(device.id)) == "visitor_99"
        assert Monitors.fingerprint("visitor_99") == "visitor_99"
        assert Monitors.fingerprint(None) is None


class TestOperationalGuards:
    def test_run_monitors_is_a_no_op_while_the_agent_is_off(self, application):
        from io import StringIO
        from django.core.management import call_command

        out = StringIO()
        call_command("run_monitors", stdout=out)
        assert "AGENT_ENABLED is off" in out.getvalue()

    def test_a_case_opening_does_not_create_an_agent_policy(self, application, no_geoip):
        with agent_on():
            open_case(application, client_id="fresh")
        assert not AgentPolicy.objects.filter(application=application).exists()
