"""
Agent FLIT: the analyst's agent on top of the decision engine.

    tools        what it can look at and change
    permissions  deny > ask > allow, across organization, application, playbook
    hooks        the bank's controls around every action
    classifier   may this write run unattended (auto mode)
    verify       an independent reader who tries to break a finding
    memory       what the organization remembers
    playbooks    the procedures, as markdown with a frontmatter
    loop         the investigation, turn by turn
    monitors     wake me when
    guardrails   kill switches, budgets, breakers
    audit        every action on the chain
"""

from .loop import InvestigationRunner, Investigations
from .permissions import PermissionRules, Decision, parse_rule, validate_rule_list
from .playbooks import Playbooks, PlaybookSpec, PlaybookError
from .memory import Memory
from .monitors import Monitors
from .guardrails import AgentGuardrails
from .tools import Tools, ToolContext, ToolError

__all__ = [
    "InvestigationRunner", "Investigations", "PermissionRules", "Decision", "parse_rule", "validate_rule_list",
    "Playbooks", "PlaybookSpec", "PlaybookError", "Memory", "Monitors", "AgentGuardrails", "Tools",
    "ToolContext", "ToolError",
]
