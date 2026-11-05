"""
The investigation loop: tools as data, the ladder, the hook, the verifier,
approvals, budgets, the report, and what goes on the chain.
"""

import json
from unittest.mock import patch

import pytest

from core.models import AgentPolicy, AgentMode, InvestigationStatus, StepStatus, Case, AuditLog
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


class TestAHappyRun:
    def test_reads_then_a_report(self, application, case):
        model = FakeModel(turns=[
            [("text", "Reading the case."), ("tool", "case_read", dict(case_id=str(case.id))), ("tool", "describe_account", dict(client_id="suspect_1"))],
            [report("needs_human", findings=[finding(tool="describe_account")])],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)

        assert investigation.status == InvestigationStatus.COMPLETED
        assert investigation.report["verdict"] == "needs_human"
        assert investigation.report["findings"][0]["verification"]["verdict"] == "confirmed"
        assert investigation.turns == 2
        assert investigation.cost_usd > 0
        steps = list(investigation.steps.order_by("index"))
        assert [s.tool for s in steps] == ["case_read", "describe_account", "report_findings"]
        assert all(s.status == StepStatus.EXECUTED for s in steps)
        assert all(s.audit_log_id for s in steps)

        results = model.tool_results()
        assert results[0]["case_id"] == str(case.id)
        assert results[0]["client_id"] == "suspect_1"
        # Identity as shape, never the string the attacker sent.
        assert "user_agent" not in json.dumps(results)
        assert results[0]["decisions"][0]["client_class"] in ("http_library", "automation", "agent", "unknown", "crawler", "browser")

    def test_the_chain_records_the_run(self, application, case):
        model = FakeModel(turns=[[("tool", "case_read", dict(case_id=str(case.id)))], [report("no_action")]])
        with agent_on():
            investigation = run(application, model=model, case=case)
        actions = list(AuditLog.objects.filter(resource_id=str(investigation.id)).values_list("action", flat=True))
        assert "agent_investigation_started" in actions and "agent_investigation_completed" in actions
        step_rows = AuditLog.objects.filter(action="agent_action", context__investigation_id=str(investigation.id))
        assert step_rows.count() == 2
        row = step_rows.first()
        assert row.actor_type == "agent" and row.category == "security"
        assert row.context["inputs_sha256"] and row.context["prompt_version"] == investigation.prompt_version

    def test_the_subject_and_budget_reach_the_model(self, application, case):
        model = FakeModel(turns=[[report("no_action")]])
        with agent_on():
            run(application, model=model, case=case)
        request = model.requests[0]
        assert "Agent FLIT" in request["system"][0]["text"]
        assert "## Playbook: investigate_case" in request["system"][0]["text"]
        assert any(t["name"] == "report_findings" for t in request["tools"])
        last_user = request["messages"][-1]["content"]
        assert "USD budget" in last_user[-1]["text"]
        assert str(case.id) in last_user[0]["text"]


class TestWritesUnderEachMode:
    def test_propose_records_and_does_not_execute(self, application, case):
        policy_for(application, mode=AgentMode.PROPOSE)
        model = FakeModel(turns=[
            [("tool", "case_resolve", dict(case_id=str(case.id), status="confirmed_fraud", note="mule pattern"))],
            [report("confirmed_fraud")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="case_resolve")
        assert step.status == StepStatus.PROPOSED
        assert step.decision == "propose"
        case.refresh_from_db()
        assert case.status == "open"
        assert model.tool_results()[0]["proposed"] is True

    def test_ask_pauses_until_a_person_answers(self, application, case):
        from core.agent import Investigations
        policy_for(application, mode=AgentMode.ASK)
        model = FakeModel(turns=[
            [("tool", "case_resolve", dict(case_id=str(case.id), status="confirmed_fraud", note="mule pattern"))],
            [report("confirmed_fraud")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
            assert investigation.status == InvestigationStatus.AWAITING_APPROVAL
            step = investigation.steps.get(tool="case_resolve")
            assert step.status == StepStatus.PENDING
            case.refresh_from_db()
            assert case.status == "open"

            owner = application.organization.owner
            investigation = Investigations.answer(step, user=owner, note="agreed", approved=True, client=model, resume=True)

        assert investigation.status == InvestigationStatus.COMPLETED
        step.refresh_from_db()
        assert step.status == StepStatus.APPROVED
        assert step.resolved_by == owner
        case.refresh_from_db()
        assert case.status == "confirmed_fraud"
        assert case.audit_log.label == "fraud"
        # The model saw the approval as the answer to its pending call.
        assert any(r.get("approved") for r in model.tool_results())

    def test_a_rejection_is_an_answer_and_the_run_continues(self, application, case):
        from core.agent import Investigations
        policy_for(application, mode=AgentMode.ASK)
        model = FakeModel(turns=[
            [("tool", "case_resolve", dict(case_id=str(case.id), status="cleared", note="looks fine"))],
            [report("needs_human")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
            step = investigation.steps.get(tool="case_resolve")
            investigation = Investigations.answer(step, user=application.organization.owner, note="no", approved=False, client=model, resume=True)
        step.refresh_from_db()
        assert step.status == StepStatus.REJECTED
        assert investigation.status == InvestigationStatus.COMPLETED
        case.refresh_from_db()
        assert case.status == "open"
        assert any(r.get("rejected") for r in model.tool_results())

    def test_an_allow_rule_lets_a_write_run_after_verification(self, application, case):
        policy_for(application, mode=AgentMode.ASK, allow=["case_note"])
        model = FakeModel(turns=[
            [("tool", "case_note", dict(case_id=str(case.id), body="checked the account"))],
            [report("no_action")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="case_note")
        assert step.status == StepStatus.EXECUTED
        assert case.notes.count() == 1 and case.notes.first().body.startswith("[agent]")

    def test_a_deny_rule_is_final(self, application, case):
        policy_for(application, mode=AgentMode.AUTO, deny=["case_resolve(cleared)"])
        model = FakeModel(turns=[
            [("tool", "case_resolve", dict(case_id=str(case.id), status="cleared", note="x"))],
            [report("needs_human")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case, mode=AgentMode.AUTO)
        step = investigation.steps.get(tool="case_resolve")
        assert step.status == StepStatus.DENIED and step.decision_source == "application:deny"
        assert model.tool_results()[0]["denied"] is True
        # The classifier was never asked about a denied call.
        assert not any("may perform one write" in (r["system"][0]["text"]) for r in model.requests if "format" in (r.get("output_config") or {}))


class TestAutoMode:
    def grant(self, application):
        policy = policy_for(application, mode=AgentMode.AUTO, auto_rules="Confirmed mule patterns may be closed as fraud.")
        policy.evaluations = {"investigate_case": dict(agreement=0.95, decided=40, n=40)}
        policy.save()
        return policy

    def test_auto_needs_a_measured_playbook(self, application, case):
        policy_for(application, mode=AgentMode.AUTO)
        model = FakeModel(turns=[[report("no_action")]])
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.mode == AgentMode.ASK

    def test_classifier_allow_then_verifier_confirm_executes(self, application, case):
        self.grant(application)
        model = FakeModel(turns=[
            [("tool", "case_resolve", dict(case_id=str(case.id), status="confirmed_fraud", note="mule"))],
            [report("confirmed_fraud")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.mode == AgentMode.AUTO
        step = investigation.steps.get(tool="case_resolve")
        assert step.status == StepStatus.EXECUTED
        assert step.decision_source == "classifier"
        assert step.verifier["verdict"] == "confirmed"
        case.refresh_from_db()
        assert case.status == "confirmed_fraud"

    def test_a_plausible_verdict_holds_the_write_for_a_person(self, application, case):
        self.grant(application)
        model = FakeModel(
            turns=[[("tool", "case_resolve", dict(case_id=str(case.id), status="confirmed_fraud", note="mule"))]],
            structured={"verify one finding": dict(verdict="plausible", reason="one line is not borne out", missing=["the device"])},
        )
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.status == InvestigationStatus.AWAITING_APPROVAL
        step = investigation.steps.get(tool="case_resolve")
        assert step.status == StepStatus.PENDING and step.decision_source == "verifier"

    def test_three_classifier_denials_drop_the_run_to_ask(self, application, case):
        self.grant(application)
        notes = [("tool", "case_note", dict(case_id=str(case.id), body=f"note {i}")) for i in range(3)]
        model = FakeModel(
            turns=[[notes[0]], [notes[1]], [notes[2]], [("tool", "case_note", dict(case_id=str(case.id), body="fourth"))], [report("no_action")]],
            structured={"may perform one write": dict(decision="deny", reason="not covered")},
        )
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.denials == 3
        assert investigation.mode == AgentMode.ASK
        # The fourth write asked a person instead of the classifier.
        fourth = investigation.steps.filter(tool="case_note").order_by("index").last()
        assert fourth.status == StepStatus.PENDING and fourth.decision_source == "mode:ask"

    def test_an_unparseable_classifier_means_ask(self, application, case):
        from core.agent.client import ModelUnavailable
        self.grant(application)
        model = FakeModel(
            turns=[[("tool", "case_note", dict(case_id=str(case.id), body="n"))]],
            structured={"may perform one write": ModelUnavailable("down")},
        )
        with agent_on():
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="case_note")
        assert step.status == StepStatus.PENDING and step.decision_source == "classifier:unavailable"


class TestTheHook:
    def hooked(self, application, answer):
        policy_for(application, mode=AgentMode.ASK, allow=["case_note"], hook_url="https://controls.bank.example/agent")
        from core.agent.hooks import AgentHooks
        return patch.object(AgentHooks, "call", classmethod(lambda cls, policy, body, timeout_ms=None: answer))

    def test_a_hook_deny_stops_an_allowed_write(self, application, case):
        model = FakeModel(turns=[[("tool", "case_note", dict(case_id=str(case.id), body="n"))], [report("no_action")]])
        with agent_on(), self.hooked(application, (200, dict(decision="deny", reason="change freeze"), None)):
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="case_note")
        assert step.status == StepStatus.DENIED and step.decision_source == "hook"
        assert step.hook["outcome"] == "deny"
        assert case.notes.count() == 0

    def test_a_hook_cannot_loosen(self, application, case):
        policy_for(application, mode=AgentMode.ASK, deny=["case_note"], hook_url="https://controls.bank.example/agent")
        from core.agent.hooks import AgentHooks
        model = FakeModel(turns=[[("tool", "case_note", dict(case_id=str(case.id), body="n"))], [report("no_action")]])
        with agent_on(), patch.object(AgentHooks, "call", classmethod(lambda cls, policy, body, timeout_ms=None: (200, dict(decision="allow"), None))):
            investigation = run(application, model=model, case=case)
        assert investigation.steps.get(tool="case_note").status == StepStatus.DENIED

    def test_an_unavailable_hook_holds_a_write_for_a_person(self, application, case):
        model = FakeModel(turns=[[("tool", "case_note", dict(case_id=str(case.id), body="n"))]])
        with agent_on(), self.hooked(application, (None, None, "connection error")):
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="case_note")
        assert step.status == StepStatus.PENDING and step.decision_source == "hook:unavailable"
        assert step.hook["outcome"] == "unavailable"

    def test_an_unavailable_hook_does_not_stop_a_read(self, application, case):
        model = FakeModel(turns=[[("tool", "case_read", dict(case_id=str(case.id)))], [report("no_action")]])
        with agent_on(), self.hooked(application, (None, None, "connection error")):
            investigation = run(application, model=model, case=case)
        assert investigation.steps.get(tool="case_read").status == StepStatus.EXECUTED

    def test_updated_input_is_taken_only_when_it_fits(self, application, case):
        model = FakeModel(turns=[[("tool", "case_note", dict(case_id=str(case.id), body="original"))], [report("no_action")]])
        answer = (200, dict(decision="allow", updated_input=dict(case_id=str(case.id), body="redacted by the hook")), None)
        with agent_on(), self.hooked(application, answer):
            investigation = run(application, model=model, case=case)
        assert case.notes.first().body == "[agent] redacted by the hook"
        bad = (200, dict(decision="allow", updated_input=dict(nonsense=1)), None)
        case2 = open_case(application, client_id="suspect_2", id="tx_2", ip_address="45.155.205.78")
        model = FakeModel(turns=[[("tool", "case_note", dict(case_id=str(case2.id), body="original"))], [report("no_action")]])
        with agent_on(), self.hooked(application, bad):
            run(application, model=model, case=case2)
        assert case2.notes.first().body == "[agent] original"


class TestLimitsAndFailures:
    def test_the_agent_off_is_a_failed_run_with_a_reason(self, application, case):
        model = FakeModel(turns=[[report("no_action")]])
        investigation = run(application, model=model, case=case)
        assert investigation.status == InvestigationStatus.FAILED
        assert "AGENT_ENABLED" in investigation.error
        assert model.requests == []

    def test_a_disabled_policy_is_off(self, application, case):
        policy_for(application, enabled=False)
        with agent_on():
            investigation = run(application, model=FakeModel(), case=case)
        assert investigation.status == InvestigationStatus.FAILED and "switched off" in investigation.error

    def test_the_turn_limit_forces_a_report(self, application, case):
        policy_for(application, max_turns=2)
        model = FakeModel(turns=[[("tool", "case_read", dict(case_id=str(case.id)))]] * 5)
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.status == InvestigationStatus.COMPLETED
        assert investigation.turns == 2
        assert investigation.report["ended_early"] == "turn limit reached"
        assert investigation.report["verdict"] == "needs_human"

    def test_the_budget_forces_a_report(self, application, case):
        policy_for(application, max_cost_usd=0.001)
        model = FakeModel(turns=[[("tool", "case_read", dict(case_id=str(case.id)))]] * 5)
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.report["ended_early"] == "budget reached"
        assert investigation.turns == 1

    def test_a_refusal_fails_the_run(self, application, case):
        model = FakeModel(turns=[["refusal"]])
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.status == InvestigationStatus.FAILED and "refused" in investigation.error

    def test_an_unknown_tool_is_denied_and_bad_inputs_fail(self, application, case):
        model = FakeModel(turns=[
            [("tool", "drop_tables", dict()), ("tool", "describe_account", dict(client_id=""))],
            [report("no_action")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
        steps = list(investigation.steps.order_by("index"))
        assert steps[0].status == StepStatus.DENIED and steps[0].decision_source == "registry"
        assert steps[1].status == StepStatus.FAILED and "schema" in model.tool_results()[1]["error"]

    def test_a_playbook_narrows_the_tools(self, application, case):
        model = FakeModel(turns=[[("tool", "case_resolve", dict(case_id=str(case.id), status="cleared", note="x"))], [report("informational")]])
        with agent_on():
            investigation = run(application, "account_review", model=model, subject=dict(client_id="suspect_1"))
        assert investigation.steps.get(tool="case_resolve").status == StepStatus.DENIED
        assert not any(t["name"] == "case_resolve" for t in model.requests[0]["tools"])

    def test_text_without_a_report_ends_in_a_forced_report(self, application, case):
        model = FakeModel(turns=[[("text", "I am done.")]])
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.status == InvestigationStatus.COMPLETED
        assert investigation.report["ended_early"] == "the model stopped without a report"

    def test_a_large_output_reaches_the_model_as_a_preview_and_digest(self, application, case):
        from core.agent.loop import InvestigationRunner
        model = FakeModel(turns=[[("tool", "case_read", dict(case_id=str(case.id)))], [report("no_action")]])
        with agent_on(), patch.object(InvestigationRunner, "MAX_OUTPUT_CHARS", 200):
            investigation = run(application, model=model, case=case)
        shown = model.tool_results()[0]
        assert shown["truncated"] is True and len(shown["sha256"]) == 64
        step = investigation.steps.get(tool="case_read")
        assert step.output_sha256 == shown["sha256"] and step.output["case_id"] == str(case.id)

    def test_a_controlled_case_is_never_cleared_by_the_agent(self, application, case):
        log = case.audit_log
        log.risk_factors = list(log.risk_factors or []) + ["sanctioned_address"]
        log.save(update_fields=["risk_factors"])
        policy_for(application, mode=AgentMode.ASK, allow=["case_resolve"])
        model = FakeModel(turns=[[("tool", "case_resolve", dict(case_id=str(case.id), status="cleared", note="fine"))], [report("needs_human")]])
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.steps.get(tool="case_resolve").status == StepStatus.FAILED
        assert "control" in model.tool_results()[0]["error"]
        case.refresh_from_db()
        assert case.status == "open"


class TestBlockActor:
    def test_a_block_becomes_a_policy_rule_the_engine_reads(self, application, case):
        policy_for(application, mode=AgentMode.ASK, allow=["block_actor(ip:*)"])
        model = FakeModel(turns=[
            [("tool", "block_actor", dict(subject="ip", pattern="45.155.205.77", reason="campaign origin", expires_hours=24))],
            [report("confirmed_fraud")],
        ])
        with agent_on():
            investigation = run(application, model=model, case=case)
        step = investigation.steps.get(tool="block_actor")
        assert step.status == StepStatus.EXECUTED and step.verifier["verdict"] == "confirmed"
        application.policy.refresh_from_db()
        rule = application.policy.rules["block"][0]
        assert rule["pattern"] == "45.155.205.77" and rule["reason"].startswith("[agent]") and rule["expires_at"]
        assert AuditLog.objects.filter(action="policy_updated", application_id=application.id).exists()

    def test_a_country_block_needs_its_own_allow(self, application, case):
        policy_for(application, mode=AgentMode.ASK, allow=["block_actor(ip:*)"])
        model = FakeModel(turns=[[("tool", "block_actor", dict(subject="country", pattern="NG", reason="x", expires_hours=24))]])
        with agent_on():
            investigation = run(application, model=model, case=case)
        assert investigation.steps.get(tool="block_actor").status == StepStatus.PENDING


class TestCompaction:
    def test_a_long_transcript_is_summarised_and_restarted(self, application, case):
        from core.agent.loop import InvestigationRunner
        model = FakeModel(turns=[[("tool", "case_read", dict(case_id=str(case.id)))], [("tool", "describe_account", dict(client_id="suspect_1"))], [report("no_action")]])
        with agent_on(), patch.object(InvestigationRunner, "COMPACT_AT_CHARS", 500):
            investigation = run(application, model=model, case=case)
        assert investigation.status == InvestigationStatus.COMPLETED
        assert investigation.compactions >= 1
        assert investigation.steps.filter(kind="compaction").exists()
        # After compaction the next request starts from the summary, not the old turns.
        compacted = next(r for r in model.requests if "format" not in (r.get("output_config") or {}) and any("continues from a summary" in b.get("text", "") for m in r["messages"] for b in m["content"] if isinstance(b, dict)))
        assert len(compacted["messages"]) <= 3


class TestCaseTrigger:
    def test_an_opened_case_queues_an_investigation_when_asked(self, application, no_geoip):
        from core.models import Investigation
        policy_for(application, investigate_cases=True)
        with agent_on():
            case = open_case(application, client_id="trig_1", id="tx_t1")
        investigation = Investigation.objects.get(case=case)
        assert investigation.status == InvestigationStatus.QUEUED
        assert investigation.playbook == "investigate_case" and investigation.trigger == "case_opened"
        assert investigation.subject["client_id"] == "trig_1"

    def test_nothing_is_queued_by_default(self, application, no_geoip):
        from core.models import Investigation
        with agent_on():
            open_case(application, client_id="trig_2", id="tx_t2")
        assert not Investigation.objects.exists()
