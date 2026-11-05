"""
Deny beats ask beats allow, across every layer, and the mode decides the rest.
"""

import pytest

from core.agent.permissions import parse_rule, rule_matches, Layer, PermissionRules, Decision, validate_rule_list
from core.agent.tools import Tools
from core.models.agent import AgentMode


BLOCK = Tools.get("block_actor")
RESOLVE = Tools.get("case_resolve")
DESCRIBE = Tools.get("describe_account")


class TestRuleSyntax:
    def test_a_bare_name_is_tool_wide(self):
        assert parse_rule("case_resolve") == ("case_resolve", None)
        assert parse_rule("case_resolve()") == ("case_resolve", None)
        assert parse_rule("case_resolve(*)") == ("case_resolve", None)

    def test_a_pattern_in_parentheses(self):
        assert parse_rule("block_actor(ip:41.58.*)") == ("block_actor", "ip:41.58.*")

    def test_matching_is_exact_without_a_star(self):
        assert rule_matches("case_resolve(cleared)", "case_resolve", "cleared")
        assert not rule_matches("case_resolve(cleared)", "case_resolve", "cleared_fraud")
        assert rule_matches("block_actor(ip:41.58.*)", "block_actor", "ip:41.58.100.7")
        assert not rule_matches("block_actor(ip:41.58.*)", "block_actor", "cidr:41.58.0.0/16")

    def test_unknown_tools_are_refused(self):
        assert validate_rule_list(["case_resolve", "nonsense"], set(Tools.names())) == ["nonsense: unknown tool nonsense"]
        assert validate_rule_list("case_resolve", set()) == ["must be a list of rules"]


class Policy:
    def __init__(self, mode=AgentMode.ASK, allow=(), ask=(), deny=()):
        self.mode, self.allow, self.ask, self.deny = mode, list(allow), list(ask), list(deny)


class TestTheLadder:
    def test_reads_are_allowed_without_a_rule(self):
        rules = PermissionRules.for_run(application_policy=Policy())
        assert rules.decide(DESCRIBE, dict(client_id="u")).behaviour == Decision.ALLOW

    def test_a_deny_anywhere_beats_an_allow_everywhere(self):
        rules = PermissionRules.for_run(
            application_policy=Policy(mode=AgentMode.AUTO, allow=["block_actor"]),
            organization_policy=Policy(mode=AgentMode.AUTO, deny=["block_actor(country:*)"]),
        )
        decision = rules.decide(BLOCK, dict(subject="country", pattern="NG"))
        assert decision.behaviour == Decision.DENY
        assert decision.source == "organization:deny"
        # The same allow still allows a narrower block.
        assert rules.decide(BLOCK, dict(subject="ip", pattern="41.58.100.7")).behaviour == Decision.ALLOW

    def test_ask_beats_allow(self):
        rules = PermissionRules.for_run(application_policy=Policy(mode=AgentMode.AUTO, allow=["case_resolve"], ask=["case_resolve(cleared)"]))
        assert rules.decide(RESOLVE, dict(status="cleared")).behaviour == Decision.ASK
        assert rules.decide(RESOLVE, dict(status="confirmed_fraud")).behaviour == Decision.ALLOW

    def test_an_organization_allow_does_not_allow_a_write(self):
        rules = PermissionRules.for_run(
            application_policy=Policy(mode=AgentMode.ASK),
            organization_policy=Policy(mode=AgentMode.AUTO, allow=["block_actor"]),
        )
        assert rules.decide(BLOCK, dict(subject="ip", pattern="1.2.3.4")).behaviour == Decision.ASK

    def test_a_deny_cannot_be_loosened_by_a_tighter_decision(self):
        deny = Decision(Decision.DENY, source="x")
        allow = Decision(Decision.ALLOW, source="hook")
        assert Decision.tighter(deny, allow) is deny
        assert Decision.tighter(allow, deny) is deny


class TestModes:
    def test_propose_records_instead_of_executing(self):
        rules = PermissionRules.for_run(application_policy=Policy(mode=AgentMode.PROPOSE, allow=["case_resolve"]))
        assert rules.decide(RESOLVE, dict(status="cleared")).behaviour == Decision.PROPOSE

    def test_ask_holds_undecided_writes(self):
        rules = PermissionRules.for_run(application_policy=Policy(mode=AgentMode.ASK))
        decision = rules.decide(RESOLVE, dict(status="cleared"))
        assert (decision.behaviour, decision.source) == (Decision.ASK, "mode:ask")

    def test_auto_hands_undecided_writes_to_the_classifier(self):
        rules = PermissionRules.for_run(application_policy=Policy(mode=AgentMode.AUTO))
        decision = rules.decide(RESOLVE, dict(status="cleared"))
        assert (decision.behaviour, decision.source) == (Decision.ASK, "mode:auto")

    def test_the_mode_is_the_tightest_of_every_layer(self):
        class Spec:
            max_mode = AgentMode.PROPOSE
            deny = ()
        rules = PermissionRules.for_run(
            application_policy=Policy(mode=AgentMode.AUTO), organization_policy=Policy(mode=AgentMode.AUTO), playbook=Spec(),
        )
        assert rules.mode == AgentMode.PROPOSE
        rules = PermissionRules.for_run(application_policy=Policy(mode=AgentMode.AUTO), organization_policy=Policy(mode=AgentMode.ASK))
        assert rules.mode == AgentMode.ASK
        rules = PermissionRules.for_run(application_policy=Policy(mode=AgentMode.AUTO), requested_mode=AgentMode.PROPOSE)
        assert rules.mode == AgentMode.PROPOSE
