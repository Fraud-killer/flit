"""
A scripted model for Agent FLIT's tests.

`turns` are the loop's answers in order: each a list of blocks, where a block
is ("text", "...") or ("tool", name, inputs). Structured calls (the classifier,
the verifier, compaction, a forced report) are recognised by their system
prompt and answered from `structured`, with sensible defaults.
"""

import json
from types import SimpleNamespace
from unittest.mock import patch


class FakeModel:
    def __init__(self, turns=(), structured=None, usage=None):
        self.turns = [list(turn) for turn in turns]
        self.structured = dict(structured or {})
        self.requests = []
        self.messages = SimpleNamespace(create=self._create)
        self.usage = usage or dict(input_tokens=1000, output_tokens=200, cache_read_input_tokens=800, cache_creation_input_tokens=0)
        self.counter = 0

    def _usage(self):
        return SimpleNamespace(**self.usage)

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        output_config = kwargs.get("output_config") or {}
        if "format" in output_config:
            return self._structured(kwargs)
        if not self.turns:
            return self._response([("text", "I have nothing further.")], stop_reason="end_turn")
        turn = self.turns.pop(0)
        if isinstance(turn, Exception):
            raise turn
        if turn and turn[0] == "refusal":
            return SimpleNamespace(stop_reason="refusal", content=[], usage=self._usage(), stop_details=SimpleNamespace(category="x"))
        has_tool = any(block[0] == "tool" for block in turn)
        return self._response(turn, stop_reason="tool_use" if has_tool else "end_turn")

    def _structured(self, kwargs):
        system = kwargs["system"][0]["text"] if isinstance(kwargs.get("system"), list) else str(kwargs.get("system"))
        for key, answer in self.structured.items():
            if key in system:
                if isinstance(answer, Exception):
                    raise answer
                if callable(answer):
                    answer = answer(kwargs)
                return self._response([("text", json.dumps(answer))], stop_reason="end_turn")
        if "verify one finding" in system:
            answer = dict(verdict="confirmed", reason="the raw outputs bear out every line", missing=[])
        elif "may perform one write" in system:
            answer = dict(decision="allow", reason="covered by the standing instructions")
        elif "summarise a fraud investigation" in system:
            answer = dict(subject="s", established=["e"], ruled_out=[], actions=[], open_questions=[], next_step="report")
        elif "investigation is ending" in system:
            answer = dict(verdict="needs_human", confidence=0.3, summary="Ended early; a person should look.", findings=[])
        else:
            raise AssertionError(f"unexpected structured call: {system[:80]}")
        return self._response([("text", json.dumps(answer))], stop_reason="end_turn")

    def _response(self, blocks, *, stop_reason):
        content = []
        for block in blocks:
            if block[0] == "text":
                content.append(SimpleNamespace(type="text", text=block[1]))
            elif block[0] == "tool":
                self.counter += 1
                content.append(SimpleNamespace(type="tool_use", id=f"toolu_{self.counter}", name=block[1], input=dict(block[2])))
        return SimpleNamespace(stop_reason=stop_reason, content=content, usage=self._usage(), stop_details=None)

    def tool_results(self):
        """Every tool_result the loop sent back, as parsed dicts, in order."""
        results = []
        for request in self.requests:
            for message in request.get("messages", []):
                if message.get("role") != "user":
                    continue
                for block in message.get("content", []):
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        text = block["content"].split("\n", 1)[1]
                        results.append(json.loads(text))
        return results


def report(verdict="needs_human", findings=None, confidence=0.7, summary="A short summary for the reviewer."):
    return ("tool", "report_findings", dict(verdict=verdict, confidence=confidence, summary=summary, findings=findings or []))


def finding(title="Something notable", tool="describe_account", severity="medium", actor=None, action=None):
    data = dict(
        title=title, severity=severity, actor=actor or dict(kind="client_id", value="user_1"),
        evidence=[dict(tool=tool, fact="the account shows the pattern")], confidence=0.8,
    )
    if action:
        data["recommended_action"] = action
    return data


def agent_on():
    from core.agent import AgentGuardrails
    return patch.object(AgentGuardrails, "enabled_globally", classmethod(lambda cls: True))


def open_case(application, **attributes):
    """A decision that opens a case, and the case."""
    from core.models import Case
    from tests.unit.test_console import risky_audit

    attributes.setdefault("client_id", "suspect_1")
    result = risky_audit(application, **attributes)
    return Case.objects.get(audit_log_id=result.audit_id)


def run(application, playbook="investigate_case", *, model, case=None, subject=None, mode=None, trigger="manual"):
    from core.agent import Investigations, InvestigationRunner

    investigation = Investigations.open(application=application, playbook=playbook, case=case, subject=subject, mode=mode, trigger=trigger)
    return InvestigationRunner.start(investigation, client=model)
