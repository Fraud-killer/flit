"""
Playbooks: markdown with a frontmatter, narrowing only, overridable per organization.
"""

import pytest

from core.agent import Playbooks, PlaybookSpec, PlaybookError


GOOD = """---
name: payout_review
description: Look at a first payout to a new address
trigger: manual
tools: describe_account, list_decisions, report_findings
max_mode: ask
max_turns: 8
---
Read the account, then the decisions. Report.
"""


class TestParsing:
    def test_a_good_playbook(self):
        spec = PlaybookSpec.parse(GOOD)
        assert spec.name == "payout_review" and spec.max_mode == "ask" and spec.max_turns == 8
        assert spec.tools == ["describe_account", "list_decisions", "report_findings"]
        assert spec.body.startswith("Read the account")

    @pytest.mark.parametrize("bad, message", [
        ("no frontmatter", "frontmatter"),
        ("---\nname: x\n---\nbody", "slug"),
        ("---\nname: ok_name\ncolour: blue\n---\nbody", "unknown frontmatter field"),
        ("---\nname: ok_name\ntools: fly_away\n---\nbody", "unknown tools"),
        ("---\nname: ok_name\nmax_mode: god\n---\nbody", "max_mode"),
        ("---\nname: ok_name\nmax_turns: 500\n---\nbody", "max_turns"),
        ("---\nname: ok_name\n---\n", "needs a body"),
    ])
    def test_bad_playbooks_are_refused(self, bad, message):
        with pytest.raises(PlaybookError, match=message):
            PlaybookSpec.parse(bad)

    def test_the_built_ins_parse(self):
        specs = Playbooks.built_in()
        assert set(specs) >= {"investigate_case", "campaign_review", "account_review", "shift_brief"}
        assert specs["investigate_case"].trigger == "case_opened"
        assert specs["shift_brief"].max_mode == "propose"


class TestOrganizations:
    def test_an_organization_overrides_a_built_in_by_name(self, application):
        organization = application.organization
        text = GOOD.replace("payout_review", "investigate_case").replace("max_mode: ask", "max_mode: propose")
        Playbooks.save(organization=organization, text=text, created_by=organization.owner)
        spec = Playbooks.resolve("investigate_case", organization)
        assert spec.source == "organization" and spec.max_mode == "propose" and spec.tools
        # Other organizations still see the built-in.
        from core.models import User, Organization
        other = Organization.objects.create(name="Other", owner=User.objects.create_user(email="o@x.io", password="x" * 12))
        assert Playbooks.resolve("investigate_case", other).source == "built-in"

    def test_an_unknown_or_disabled_playbook_is_refused(self, application):
        organization = application.organization
        with pytest.raises(PlaybookError, match="no playbook"):
            Playbooks.resolve("nothing_here", organization)
        row = Playbooks.save(organization=organization, text=GOOD)
        row.enabled = False
        row.save()
        with pytest.raises(PlaybookError, match="disabled"):
            Playbooks.resolve("payout_review", organization)
