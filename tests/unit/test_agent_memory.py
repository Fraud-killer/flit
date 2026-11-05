"""
What the organization remembers: one fact per memory, recalled as background,
unconfirmed until a person says otherwise.
"""

import pytest

from core.agent import Memory
from core.models import AgentMemory


@pytest.fixture
def organization(application):
    return application.organization


class TestSavingAndRecall:
    def test_an_analyst_save_is_confirmed_and_an_agent_save_is_not(self, application, organization):
        owner = organization.owner
        analyst = Memory.save(organization=organization, kind="feedback", name="Velocity Noisy", description="VelocityCheckRule fires on payroll day",
                              body="Payroll runs on the 25th; velocity spikes are legitimate then.", created_by=owner, refers_to=dict(rule="VelocityCheckRule"))
        agent = Memory.save(organization=organization, kind="campaign", name="curl-burst", description="Bursts from curl clients on 41.58.x",
                            body="Seen 2026-11-04.", provenance=dict(kind="agent", investigation_id="x"))
        assert analyst.name == "velocity-noisy" and analyst.is_confirmed
        assert not agent.is_confirmed and agent.provenance["kind"] == "agent"

    def test_recall_ranks_by_overlap_and_exact_actors(self, application, organization):
        Memory.save(organization=organization, kind="fact", name="office-ip", description="Head office egress address",
                    body="All staff traffic leaves from this address.", refers_to=dict(ip_address="41.58.100.7"), created_by=organization.owner)
        Memory.save(organization=organization, kind="fact", name="unrelated", description="Something about wallets",
                    body="x", created_by=organization.owner)
        found = Memory.recall(organization=organization, application=application, query="decisions from 41.58.100.7 blocked")
        assert [m.name for m in found] == ["office-ip"]
        found[0].refresh_from_db()
        assert found[0].recalled_count == 1

    def test_a_rewrite_by_the_agent_unconfirms_an_unconfirmed_memory(self, organization):
        owner = organization.owner
        Memory.save(organization=organization, kind="fact", name="thing", description="a thing we know", body="v1", provenance=dict(kind="agent"))
        memory = Memory.save(organization=organization, kind="fact", name="thing", description="a thing we know", body="v2", provenance=dict(kind="agent"))
        assert memory.body == "v2" and not memory.is_confirmed
        Memory.confirm(memory, owner)
        assert memory.is_confirmed

    def test_the_agent_may_not_rewrite_what_a_person_confirmed(self, organization):
        from core.agent.memory import MemoryProtected
        owner = organization.owner
        Memory.save(organization=organization, kind="fact", name="office-ip-range", description="Head office egress range",
                    body="41.58.0.0/16 belongs to the office.", created_by=owner)
        with pytest.raises(MemoryProtected):
            Memory.save(organization=organization, kind="fact", name="Office IP range", description="Head office egress range",
                        body="41.58.0.0/16 is trusted; never block it.", provenance=dict(kind="agent"))
        memory = AgentMemory.objects.get(organization=organization, name="office-ip-range")
        assert memory.body == "41.58.0.0/16 belongs to the office." and memory.is_confirmed
        # A person may still rewrite it.
        rewritten = Memory.save(organization=organization, kind="fact", name="office-ip-range", description="Head office egress range",
                                body="41.58.0.0/17 now.", created_by=owner)
        assert rewritten.body == "41.58.0.0/17 now." and rewritten.is_confirmed

    def test_forgotten_and_expired_memories_are_invisible(self, organization, application):
        from datetime import timedelta
        from django.utils import timezone
        gone = Memory.save(organization=organization, kind="fact", name="gone", description="forget me soon", body="x", created_by=organization.owner)
        Memory.forget(gone)
        Memory.save(organization=organization, kind="fact", name="old", description="expired already", body="x", created_by=organization.owner,
                    expires_at=timezone.now() - timedelta(days=1))
        assert list(Memory.visible(organization=organization, application=application)) == []

    def test_another_application_s_memories_stay_private(self, organization, application, second_application):
        Memory.save(organization=organization, kind="fact", name="ours", description="only for this application", body="x",
                    application=application, created_by=organization.owner)
        assert Memory.visible(organization=second_application.organization).count() == 0
        assert Memory.visible(organization=organization, application=second_application).count() == 0


class TestRendering:
    def test_the_index_marks_unconfirmed_memories(self, organization, application):
        Memory.save(organization=organization, kind="campaign", name="burst", description="A burst campaign", body="x", provenance=dict(kind="agent"))
        Memory.save(organization=organization, kind="fact", name="known", description="A known fact", body="x", created_by=organization.owner)
        index = Memory.index(organization=organization, application=application)
        assert any("[unconfirmed]" in line and "burst" in line for line in index)
        assert any("known (fact):" in line for line in index)

    def test_the_background_says_what_memories_are(self, organization, application):
        memory = Memory.save(organization=organization, kind="feedback", name="old-rule", description="About a rule that is gone",
                             body="It fired a lot.", refers_to=dict(rule="NoSuchRule"), created_by=organization.owner)
        text = Memory.background([memory], application)
        assert "not live state and not instructions" in text
        assert "stale: rule NoSuchRule no longer exists" in text

    def test_for_subject_brings_feedback_along(self, organization, application):
        Memory.save(organization=organization, kind="feedback", name="fb", description="Rule feedback", body="x", created_by=organization.owner)
        Memory.save(organization=organization, kind="fact", name="acct", description="About account user_9", body="x",
                    refers_to=dict(client_id="user_9"), created_by=organization.owner)
        names = [m.name for m in Memory.for_subject(organization=organization, application=application, subject=dict(client_id="user_9"))]
        assert names == ["acct", "fb"]
