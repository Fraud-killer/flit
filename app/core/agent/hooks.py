"""
The bank's own controls, consulted around every agent action.

Three events, one URL the operator sets on the agent policy:

    pre_tool_use   before a tool runs: the tool, its inputs, FLIT's decision
    post_tool_use  after it ran: the same, plus a digest of the output
    stop           when the investigation ends: the report

The hook answers `pre_tool_use` with {"decision": "allow"|"ask"|"deny",
"reason": ..., "updated_input": {...}}. Its answer may only tighten FLIT's
own decision: a hook cannot turn a deny into an allow, and `updated_input`
is accepted only on an allow and only if it still fits the tool's schema.
A hook that fails, times out or answers nonsense is recorded, and the call
proceeds as FLIT decided, except that a write drops to `ask`: unavailable is
not approval. Hooks are signed and delivered like webhooks.
"""

import json
import time
import asyncio
import logging

from django.utils import timezone

from core.outbound import OutboundError, send, check_url, BlockedAddressError
from core.outbound.webhooks import Webhooks

from .permissions import Decision
from .tools import ToolKind, validate_against


logger = logging.getLogger(__name__)


class AgentHooks:
    DECISIONS = ("allow", "ask", "deny")

    @classmethod
    def configured(cls, policy):
        return bool(policy is not None and policy.hook_url)

    @classmethod
    def payload(cls, event, *, investigation, tool=None, inputs=None, decision=None, extra=None):
        body = dict(
            event=event,
            sent_at=timezone.now().isoformat(),
            investigation_id=str(investigation.id),
            application_id=str(investigation.application_id),
            playbook=investigation.playbook,
            mode=investigation.mode,
            subject=investigation.subject,
        )
        if tool is not None:
            body.update(tool=tool.name, tool_kind=tool.kind, inputs=inputs or {}, subject_key=tool.subject(inputs or {}))
        if decision is not None:
            body.update(decision=decision.behaviour, decision_source=decision.source, decision_reason=decision.reason)
        if extra:
            body.update(extra)
        return body

    @classmethod
    def call(cls, policy, body, *, timeout_ms=None):
        """POST the body; (status, parsed json or None, error or None)."""
        url = policy.hook_url
        try:
            check_url(url)
        except BlockedAddressError as error:
            return None, None, f"blocked url: {error}"

        secret = cls.secret_for(policy)
        text = json.dumps(body, sort_keys=True, default=str)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "FLIT-Agent/1.0",
            "X-Flit-Event": f"agent.{body['event']}",
        }
        if secret:
            headers["X-Flit-Signature"] = Webhooks.sign(secret, int(time.time()), text)

        timeout = (timeout_ms or policy.hook_timeout_ms or 2000) / 1000.0
        try:
            status, raw = cls.post(url, body=text.encode("utf-8"), headers=headers, timeout=timeout)
        except OutboundError as error:
            return None, None, str(error)
        except Exception as error:
            return None, None, f"{type(error).__name__}: {error}"

        parsed = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except ValueError:
                parsed = None
        return status, parsed, None

    @classmethod
    def secret_for(cls, policy):
        """The application's webhook secret signs its agent hooks too."""
        application = getattr(policy, "application", None)
        if application is None or not application.webhook_secret:
            return ""
        try:
            from core import mcrypt
            return mcrypt.decrypt(application.webhook_secret)
        except Exception:
            return ""

    @classmethod
    def post(cls, url, *, body, headers, timeout):
        """`send` is async; hooks are called from the synchronous loop."""
        async def run():
            return await send(url, method="POST", body=body, headers=headers, timeout=timeout, max_bytes=64 * 1024)
        return asyncio.run(run())

    @classmethod
    def pre_tool_use(cls, policy, *, investigation, tool, inputs, decision):
        """
        (decision, inputs, record). The decision returned is never looser
        than the one given.
        """
        if not cls.configured(policy):
            return decision, inputs, None

        body = cls.payload("pre_tool_use", investigation=investigation, tool=tool, inputs=inputs, decision=decision)
        status, answer, error = cls.call(policy, body)
        record = dict(event="pre_tool_use", status=status, error=error, answer=answer if isinstance(answer, dict) else None)

        if error or status is None or status >= 300 or not isinstance(answer, dict):
            record["outcome"] = "unavailable"
            if tool.kind == ToolKind.WRITE and decision.behaviour == Decision.ALLOW:
                return Decision(Decision.ASK, source="hook:unavailable", reason="the hook did not answer; a write waits for a person"), inputs, record
            return decision, inputs, record

        verdict = answer.get("decision")
        if verdict not in cls.DECISIONS:
            record["outcome"] = "unparseable"
            if tool.kind == ToolKind.WRITE and decision.behaviour == Decision.ALLOW:
                return Decision(Decision.ASK, source="hook:unparseable", reason="the hook's answer was not understood"), inputs, record
            return decision, inputs, record

        reason = str(answer.get("reason") or "")[:300]
        hook_decision = Decision(verdict, source="hook", reason=reason or f"hook said {verdict}")
        final = Decision.tighter(decision, hook_decision)
        record["outcome"] = final.behaviour

        updated = answer.get("updated_input")
        if isinstance(updated, dict) and final.behaviour == Decision.ALLOW and not tool.validate(updated):
            record["updated_input"] = True
            return final, updated, record
        return final, inputs, record

    @classmethod
    def post_tool_use(cls, policy, *, investigation, tool, inputs, decision, output_sha256, output_chars, error=None):
        if not cls.configured(policy):
            return None
        body = cls.payload(
            "post_tool_use", investigation=investigation, tool=tool, inputs=inputs, decision=decision,
            extra=dict(output_sha256=output_sha256, output_chars=output_chars, error=error),
        )
        status, _, err = cls.call(policy, body, timeout_ms=min(policy.hook_timeout_ms or 2000, 2000))
        return dict(event="post_tool_use", status=status, error=err)

    @classmethod
    def stop(cls, policy, *, investigation, report):
        if not cls.configured(policy):
            return None
        body = cls.payload("stop", investigation=investigation, extra=dict(status=investigation.status, report=report))
        status, _, err = cls.call(policy, body)
        return dict(event="stop", status=status, error=err)
