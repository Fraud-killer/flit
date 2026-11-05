"""
The report: how an investigation ends.

Findings are typed, not prose. Each names an actor, cites the evidence by the
tool call that produced it, says how severe it is and what, if anything, the
agent recommends. The verdict is one of a fixed set. A report without
findings is a legitimate outcome.
"""

from .base import Tool, ToolKind


VERDICTS = ("confirmed_fraud", "cleared", "needs_human", "no_action", "informational")
SEVERITIES = ("critical", "high", "medium", "low", "info")

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "minLength": 3, "maxLength": 120},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "actor": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["client_id", "device", "ip", "cidr", "email_root", "wallet", "campaign", "rule", "application"]},
                "value": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            "required": ["kind", "value"],
            "additionalProperties": False,
        },
        "evidence": {
            "type": "array",
            "minItems": 1,
            "maxItems": 12,
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "minLength": 1, "maxLength": 60},
                    "fact": {"type": "string", "minLength": 3, "maxLength": 300},
                },
                "required": ["tool", "fact"],
                "additionalProperties": False,
            },
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "recommended_action": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "enum": ["case_resolve", "block_actor", "policy_change", "open_monitor", "none"]},
                "inputs": {"type": "object"},
                "why": {"type": "string", "maxLength": 300},
            },
            "required": ["tool", "why"],
            "additionalProperties": False,
        },
    },
    "required": ["title", "severity", "actor", "evidence", "confidence"],
    "additionalProperties": False,
}

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "summary": {"type": "string", "minLength": 10, "maxLength": 1200},
        "findings": {"type": "array", "items": FINDING_SCHEMA, "maxItems": 20},
        "open_questions": {"type": "array", "items": {"type": "string", "maxLength": 200}, "maxItems": 8},
    },
    "required": ["verdict", "confidence", "summary", "findings"],
    "additionalProperties": False,
}


class ReportFindingsTool(Tool):
    name = "report_findings"
    kind = ToolKind.READ
    terminal = True
    description = (
        "End the investigation with a typed report: a verdict, a confidence, a summary a "
        "reviewer reads in ten seconds, and findings. Each finding names one actor, cites "
        "the tool calls that are its evidence, and may recommend one action. Call this "
        "exactly once, when the facts are in. needs_human is always acceptable."
    )
    input_schema = REPORT_SCHEMA

    @classmethod
    def run(cls, inputs, context):
        return dict(accepted=True, findings=len(inputs.get("findings") or []))
