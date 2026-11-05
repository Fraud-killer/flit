"""
A merchant's own logic, consulted before the decision is final.

Some things only the merchant knows: this account is a staff member, that
counterparty is on an internal watchlist, this card was reported lost ten
minutes ago. The decision hook is where that knowledge gets a vote. FLIT
posts the decision it is about to return; the merchant's endpoint answers
with the decision it wants, and a reason.

The vote can only go one way. A hook may turn an allow into a review, a
review into a challenge, a challenge into a block. It may not loosen
anything: the hook is reachable with the application key, and a leaked key
that could whitelist its own traffic is the attacker's dream integration.
A hook that times out or errors is recorded and ignored — a merchant's bug
must not take the merchant's checkout down with it.
"""

import json
import logging
import time

from core import mcrypt

from .client import OutboundError, send
from .ssrf import BlockedAddressError
from .webhooks import Webhooks


logger = logging.getLogger(__name__)


DECISIONS = ("allow", "review", "challenge", "block")
RANK = {name: index for index, name in enumerate(DECISIONS)}
DEFAULT_TIMEOUT_MS = 150


class DecisionHook:
    @classmethod
    def current(cls, risk_result):
        if risk_result.should_block:
            return "block"
        if risk_result.should_challenge:
            return "challenge"
        if risk_result.should_review:
            return "review"
        return "allow"

    @classmethod
    async def consult(cls, *, application, event, risk_result, decision):
        """
        Ask the hook; returns a record of what happened, and applies a
        tightening to `risk_result` in place.
        """
        url = getattr(application, "decision_hook_url", None)
        if not url:
            return None

        timeout_ms = getattr(application, "decision_hook_timeout_ms", None) or DEFAULT_TIMEOUT_MS
        before = cls.current(risk_result)
        started = time.monotonic()

        body = json.dumps(dict(
            application_id=str(application.id),
            event=dict(
                id=getattr(event, "id", None),
                client_id=event.account_id,
                type=type(event).__name__,
            ),
            decision=dict(decision, current=before),
        ), sort_keys=True, default=str)

        secret = mcrypt.decrypt(application.webhook_secret) if getattr(application, "webhook_secret", None) else ""
        timestamp = int(time.time())
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "FLIT-DecisionHook/1.0",
            "X-Flit-Signature": Webhooks.sign(secret, timestamp, body),
        }

        record = dict(url=url, before=before, applied=False)

        try:
            status, raw = await send(
                url, body=body.encode("utf-8"), headers=headers, timeout=timeout_ms / 1000.0,
            )
            record["status"] = status
            if not 200 <= status < 300:
                record["error"] = f"status {status}"
                return cls._finish(record, started)
            try:
                answer = json.loads(raw.decode("utf-8") or "{}")
            except ValueError:
                record["error"] = "body is not JSON"
                return cls._finish(record, started)
        except BlockedAddressError as error:
            record["error"] = f"refused: {error}"
            return cls._finish(record, started)
        except OutboundError as error:
            record["error"] = str(error)[:200]
            return cls._finish(record, started)

        wanted = str((answer or {}).get("decision", "")).lower()
        record["decision"] = wanted or None
        record["reason"] = str((answer or {}).get("reason", ""))[:300] or None

        if wanted not in RANK:
            record["error"] = "no decision in answer"
            return cls._finish(record, started)

        if RANK[wanted] <= RANK[before]:
            # Same or looser: noted, not applied.
            return cls._finish(record, started)

        cls.tighten(risk_result, wanted)
        record["applied"] = True
        record["after"] = wanted
        return cls._finish(record, started)

    @staticmethod
    def tighten(risk_result, wanted):
        if wanted == "block":
            risk_result.should_block = True
            risk_result.should_challenge = False
            risk_result.should_review = True
        elif wanted == "challenge":
            risk_result.should_challenge = True
            risk_result.should_review = True
        elif wanted == "review":
            risk_result.should_review = True

    @staticmethod
    def _finish(record, started):
        record["latency_ms"] = round((time.monotonic() - started) * 1000)
        if record.get("error"):
            logger.info("Decision hook %s: %s", record["url"], record["error"])
        return record
