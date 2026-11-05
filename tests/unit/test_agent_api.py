"""
The console surface: the agent's policy with its loosening guard,
investigations and approvals, memories, monitors, playbooks. Three things need
a person; an application key is refused.
"""

import pytest

from core.models import AgentPolicy, AgentMode, InvestigationStatus
from tests.unit.agent_fakes import FakeModel, report, agent_on, open_case
from tests.unit.test_policy_api import app_client, owner_client


def url(application, path):
    return f"/api/v1/applications/{application.id}/{path}"


def org_url(application, path):
    return f"/api/v1/organizations/{application.organization.id}/{path}"


class TestAgentPolicy:
    def test_the_defaults(self, application):
        response = app_client(application).get(url(application, "agent-policy"))
        data = response.data["data"]
        assert response.status_code == 200
        assert data["mode"] == "propose" and data["enabled"] is True
        assert data["effective_mode"] == "propose"
        assert any(t["name"] == "block_actor" and t["kind"] == "write" for t in data["tools"])

    def test_an_application_key_may_tighten(self, application):
        response = app_client(application).patch(url(application, "agent-policy"), dict(deny=["policy_change"], max_turns=10), format="json")
        assert response.status_code == 200
        assert response.data["data"]["deny"] == ["policy_change"]

    def test_an_application_key_may_not_loosen(self, application):
        response = app_client(application).patch(url(application, "agent-policy"), dict(mode="auto"), format="json")
        assert response.status_code == 403
        assert response.data["errors"][0]["code"] == "agent_policy_loosening_forbidden"
        assert "mode propose → auto" in response.data["errors"][0]["context"]["loosened"]
        assert AgentPolicy.for_application(application).mode == "propose"

    def test_an_owner_may_loosen_and_the_chain_says_so(self, application):
        from core.models import AuditLog
        response = owner_client(application).patch(url(application, "agent-policy"), dict(mode="ask", allow=["case_note"], investigate_cases=True), format="json")
        assert response.status_code == 200
        assert response.data["data"]["mode"] == "ask"
        row = AuditLog.objects.get(action="agent_policy_loosened")
        assert "allow rules added: case_note" in row.context["loosened"]

    def test_bad_rules_and_urls_are_refused(self, application):
        response = owner_client(application).patch(url(application, "agent-policy"), dict(deny=["nope"], hook_url="http://10.0.0.1/x"), format="json")
        assert response.status_code == 400
        codes = {e["code"] for e in response.data["errors"]}
        assert codes == {"agent_rules_invalid", "outbound_url"}

    def test_the_organization_ceiling_is_owner_only(self, application):
        assert app_client(application).get(org_url(application, "agent-policy")).status_code == 403
        response = owner_client(application).patch(org_url(application, "agent-policy"), dict(mode="ask", deny=["policy_change"]), format="json")
        assert response.status_code == 200
        shown = app_client(application).get(url(application, "agent-policy")).data["data"]
        assert shown["organization"]["deny"] == ["policy_change"]
        assert shown["effective_mode"] == "propose"


class TestInvestigations:
    def test_off_is_a_409(self, application):
        response = app_client(application).post(url(application, "investigations"), dict(client_id="u1", playbook="account_review"), format="json")
        assert response.status_code == 409
        assert response.data["errors"][0]["code"] == "agent_disabled"

    def test_an_investigation_is_queued_then_run_by_the_worker(self, application, no_geoip):
        from io import StringIO
        from django.core.management import call_command
        from core.agent import InvestigationRunner

        case = open_case(application)
        with agent_on():
            response = app_client(application).post(url(application, "investigations"), dict(case_id=str(case.id)), format="json")
        assert response.status_code == 202
        shown = response.data["data"]["investigation"]
        assert shown["status"] == "queued" and shown["subject"]["client_id"] == "suspect_1"

        model = FakeModel(turns=[[report("needs_human")]])
        with agent_on(), pytest.MonkeyPatch.context() as mp:
            mp.setattr(InvestigationRunner, "start", classmethod(lambda cls, inv, client=None: InvestigationRunner(inv, client=model).run()))
            out = StringIO()
            call_command("run_investigations", limit=5, stdout=out)
        assert "completed" in out.getvalue()

        detail = app_client(application).get(url(application, f"investigations/{shown['id']}")).data["data"]["investigation"]
        assert detail["status"] == "completed" and detail["report"]["verdict"] == "needs_human"
        assert detail["steps"][-1]["tool"] == "report_findings"

        listed = app_client(application).get(url(application, "investigations?status=completed")).data["data"]
        assert listed["total"] == 1

    def test_another_merchant_cannot_see_it(self, application, second_application, no_geoip):
        case = open_case(application)
        with agent_on():
            created = app_client(application).post(url(application, "investigations"), dict(case_id=str(case.id)), format="json").data["data"]["investigation"]
        response = app_client(second_application).get(url(application, f"investigations/{created['id']}"))
        assert response.status_code == 403
        response = app_client(second_application).get(url(second_application, f"investigations/{created['id']}"))
        assert response.status_code == 400

    def test_approval_needs_a_person(self, application, no_geoip):
        from core.agent import InvestigationRunner, Investigations
        policy = AgentPolicy.for_application(application)
        policy.mode = AgentMode.ASK
        policy.save()
        case = open_case(application)
        model = FakeModel(turns=[
            [("tool", "case_resolve", dict(case_id=str(case.id), status="confirmed_fraud", note="mule"))],
            [report("confirmed_fraud")],
        ])
        with agent_on():
            investigation = Investigations.open(application=application, playbook="investigate_case", case=case)
            InvestigationRunner.start(investigation, client=model)
        step = investigation.steps.get(tool="case_resolve")
        path = url(application, f"investigations/{investigation.id}/steps/{step.id}")

        refused = app_client(application).patch(path, dict(decision="approve"), format="json")
        assert refused.status_code == 403 and refused.data["errors"][0]["code"] == "person_required"

        approved = owner_client(application).patch(path, dict(decision="approve", note="agreed"), format="json")
        assert approved.status_code == 200
        assert approved.data["data"]["step"]["status"] == "approved"
        assert approved.data["data"]["step"]["resolved_by"] == application.organization.owner.email
        assert approved.data["data"]["investigation"]["status"] == "queued"
        case.refresh_from_db()
        assert case.status == "confirmed_fraud"

        again = owner_client(application).patch(path, dict(decision="approve"), format="json")
        assert again.status_code == 409

    def test_cancelling(self, application, no_geoip):
        case = open_case(application)
        with agent_on():
            created = app_client(application).post(url(application, "investigations"), dict(case_id=str(case.id)), format="json").data["data"]["investigation"]
        response = app_client(application).patch(url(application, f"investigations/{created['id']}"), dict(status="cancelled"), format="json")
        assert response.status_code == 200 and response.data["data"]["investigation"]["status"] == "cancelled"
        assert app_client(application).patch(url(application, f"investigations/{created['id']}"), dict(status="cancelled"), format="json").status_code == 409


class TestMemories:
    def test_a_person_saves_and_confirms(self, application):
        body = dict(kind="fact", name="Office IP", description="Head office egress address", body="41.58.100.7 is ours.", refers_to=dict(ip_address="41.58.100.7"))
        assert app_client(application).post(url(application, "memories"), body, format="json").status_code == 403
        response = owner_client(application).post(url(application, "memories"), body, format="json")
        assert response.status_code == 201
        memory = response.data["data"]["memory"]
        assert memory["name"] == "office-ip" and memory["confirmed"] is True

        listed = app_client(application).get(url(application, "memories?q=41.58.100.7")).data["data"]
        assert [m["name"] for m in listed["memories"]] == ["office-ip"]
        assert listed["index"][0].startswith("- office-ip (fact):")

        assert owner_client(application).delete(url(application, f"memories/{memory['id']}")).status_code == 200
        assert app_client(application).get(url(application, "memories")).data["data"]["memories"] == []

    def test_an_agent_memory_is_confirmed_by_a_person(self, application):
        from core.agent import Memory
        memory = Memory.save(organization=application.organization, kind="campaign", name="burst", description="A burst from curl",
                             body="x", provenance=dict(kind="agent"))
        response = owner_client(application).patch(url(application, f"memories/{memory.id}"), dict(confirmed=True), format="json")
        assert response.status_code == 200 and response.data["data"]["memory"]["confirmed"] is True


class TestMonitorsAndPlaybooks:
    def test_monitors(self, application):
        response = app_client(application).post(url(application, "monitors"), dict(name="watch m", metric="blocks", threshold=3, client_id="m1", expires_hours=12), format="json")
        assert response.status_code == 201
        monitor = response.data["data"]["monitor"]
        assert monitor["subject"] == dict(client_id="m1") and monitor["status"] == "active"
        bad = app_client(application).post(url(application, "monitors"), dict(name="x", metric="factor", threshold=1), format="json")
        assert bad.status_code == 400
        assert app_client(application).delete(url(application, f"monitors/{monitor['id']}")).data["data"]["monitor"]["status"] == "cancelled"

    def test_playbooks_are_listed_for_the_application_and_written_by_the_owner(self, application):
        listed = app_client(application).get(url(application, "playbooks")).data["data"]["playbooks"]
        assert {p["name"] for p in listed} >= {"investigate_case", "shift_brief"}

        text = "---\nname: payout_review\ndescription: First payout\ntools: describe_account, report_findings\nmax_mode: ask\n---\nRead, then report.\n"
        assert app_client(application).put(org_url(application, "playbooks"), dict(text=text), format="json").status_code == 403
        response = owner_client(application).put(org_url(application, "playbooks"), dict(text=text), format="json")
        assert response.status_code == 201 and response.data["data"]["playbook"]["source"] == "organization"

        bad = owner_client(application).put(org_url(application, "playbooks"), dict(text="---\nname: x\n---\nbody"), format="json")
        assert bad.status_code == 400 and bad.data["errors"][0]["code"] == "playbook_invalid"

        assert owner_client(application).delete(org_url(application, "playbooks/payout_review")).data["data"]["deleted"] is True
