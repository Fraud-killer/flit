"""
The tool registry: the one list of what the agent can do.

Like `Auditor.rule_classes`, a tuple. A playbook may narrow it; nothing may
widen it. Names are stable, because permission rules and hooks match on them.
"""

from .base import Tool, ToolKind, ToolError, ToolContext, sanitize, validate_against
from .read_tools import READ_TOOLS, decision_facts
from .write_tools import WRITE_TOOLS
from .report import ReportFindingsTool, REPORT_SCHEMA, VERDICTS, SEVERITIES


class Tools:
    registry = READ_TOOLS + WRITE_TOOLS + (ReportFindingsTool,)

    @classmethod
    def by_name(cls):
        return {tool.name: tool for tool in cls.registry}

    @classmethod
    def get(cls, name):
        tool = cls.by_name().get(name)
        if tool is None:
            raise ToolError(f"Unknown tool {name}")
        return tool

    @classmethod
    def names(cls):
        return tuple(tool.name for tool in cls.registry)

    @classmethod
    def select(cls, allowed=None):
        """The registry narrowed to `allowed` names. The report tool is always present."""
        if not allowed:
            return cls.registry
        wanted = set(allowed) | {ReportFindingsTool.name}
        return tuple(tool for tool in cls.registry if tool.name in wanted)

    @classmethod
    def definitions(cls, tools=None):
        return [tool.definition() for tool in (tools or cls.registry)]


__all__ = [
    "Tool", "ToolKind", "ToolError", "ToolContext", "Tools", "sanitize", "validate_against",
    "decision_facts", "ReportFindingsTool", "REPORT_SCHEMA", "VERDICTS", "SEVERITIES",
]
