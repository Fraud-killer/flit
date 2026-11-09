"""
Telling the merchant what happened, signed, with retries.

FLIT returns a decision in the response to every audit. What a response
cannot carry is what happens afterwards: the case that opened, the challenge
that failed an hour later, the campaign that emerged across twenty requests,
the calibration that moved a weight overnight. Those go to the merchant's
webhook.

Every delivery is signed with the application's webhook secret the way the
merchant signs requests to FLIT, so the merchant can refuse anything else:

    X-Flit-Event:      case.opened
    X-Flit-Delivery:   <delivery id>
    X-Flit-Signature:  t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>

Delivery goes through the SSRF guard like every other outbound call; a
webhook URL pointing inside the network is refused before a socket opens.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import random
import time
from datetime import timedelta

from django.utils import timezone

from core import mcrypt
from core.models.webhook import WebhookDelivery, WebhookStatus

from .client import OutboundError, send
from .ssrf import BlockedAddressError


logger = logging.getLogger(__name__)


EVENTS = (
    "decision.blocked",
    "decision.review",
    "case.opened",
    "campaign.detected",
    "challenge.passed",
    "challenge.failed",
    "calibration.applied",
    "policy.loosened",
    "investigation.completed",
    "agent.approval_requested",
    "monitor.fired",
    "outflow.tripped",
)

TIMEOUT_SECONDS = 10
# Retry delays: 30 s, 60 s, 2 min, 4 min ... capped at an hour, with jitter so
# a merchant coming back from an outage is not hit by every queued delivery
# in the same second.
BASE_DELAY_SECONDS = 30
MAX_DELAY_SECONDS = 3600


class Webhooks:
    @classmethod
    def subscribed(cls, application, event):
        url = getattr(application, "webhook_url", None)
        if not url:
            return False
        chosen = getattr(application, "webhook_events", None) or []
        return event in chosen if chosen else event in EVENTS

    @classmethod
    def enqueue(cls, application, event, payload):
        """Queue one event for the merchant, if they want it. Never raises."""
        try:
            if not cls.subscribed(application, event):
                return None
            return WebhookDelivery.objects.create(
                application=application, event=event, payload=payload,
                next_attempt_at=timezone.now(),
            )
        except Exception:
            logger.exception("Could not queue webhook %s", event)
            return None

    @classmethod
    def sign(cls, secret, timestamp, body):
        digest = hmac.new(
            secret.encode("utf-8"), f"{timestamp}.{body}".encode("utf-8"), hashlib.sha256,
        ).hexdigest()
        return f"t={timestamp},v1={digest}"

    @classmethod
    def verify_signature(cls, secret, header, body, *, tolerance_seconds=300, now=None):
        """What a merchant's server does with the header. Here so it is tested."""
        try:
            parts = dict(item.split("=", 1) for item in header.split(","))
            timestamp = int(parts["t"])
        except (ValueError, KeyError, AttributeError):
            return False
        now = now or int(time.time())
        if abs(now - timestamp) > tolerance_seconds:
            return False
        expected = cls.sign(secret, timestamp, body)
        return hmac.compare_digest(expected, header)

    @classmethod
    def body_for(cls, delivery):
        return json.dumps(dict(
            id=str(delivery.id),
            event=delivery.event,
            application_id=str(delivery.application_id),
            created_at=delivery.created_at.isoformat() if delivery.created_at else None,
            data=delivery.payload,
        ), sort_keys=True, default=str)

    @classmethod
    async def deliver(cls, delivery):
        """One attempt. Returns True when the merchant accepted it."""
        from asgiref.sync import sync_to_async

        prepared = await sync_to_async(cls._prepare)(delivery)
        status, error, refused = None, "", False

        try:
            status, _ = await send(
                prepared["url"], body=prepared["body"], headers=prepared["headers"],
                timeout=TIMEOUT_SECONDS,
            )
        except BlockedAddressError as failure:
            # Not a transient failure: the URL itself is unacceptable.
            error, refused = f"refused: {failure}", True
        except OutboundError as failure:
            error = str(failure)[:500]

        return await sync_to_async(cls._finish)(delivery, status, error, refused)

    @classmethod
    def _prepare(cls, delivery):
        application = delivery.application
        secret = mcrypt.decrypt(application.webhook_secret) if application.webhook_secret else ""
        body = cls.body_for(delivery)
        timestamp = int(time.time())

        return dict(
            url=application.webhook_url,
            body=body.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "FLIT-Webhooks/1.0",
                "X-Flit-Event": delivery.event,
                "X-Flit-Delivery": str(delivery.id),
                "X-Flit-Signature": cls.sign(secret, timestamp, body),
            },
        )

    @classmethod
    def _finish(cls, delivery, status, error, refused):
        delivery.attempts += 1
        delivery.last_status_code = status
        delivery.last_error = error
        accepted = status is not None and 200 <= status < 300

        if refused:
            delivery.status = WebhookStatus.DEAD
        elif accepted:
            delivery.status = WebhookStatus.DELIVERED
            delivery.delivered_at = timezone.now()
        elif delivery.attempts >= WebhookDelivery.MAX_ATTEMPTS:
            delivery.status = WebhookStatus.DEAD
        else:
            delivery.next_attempt_at = timezone.now() + timedelta(seconds=cls.delay(delivery.attempts))

        delivery.save()
        return accepted

    @classmethod
    def delay(cls, attempts):
        base = min(BASE_DELAY_SECONDS * (2 ** (attempts - 1)), MAX_DELAY_SECONDS)
        return base + random.uniform(0, base * 0.25)

    @classmethod
    def due(cls, limit=200):
        return list(
            WebhookDelivery.objects
            .filter(status=WebhookStatus.PENDING, next_attempt_at__lte=timezone.now())
            .select_related("application")
            .order_by("next_attempt_at")[:limit]
        )

    @classmethod
    def drain(cls, limit=200):
        """Deliver everything due; returns (delivered, failed)."""
        deliveries = cls.due(limit)
        if not deliveries:
            return 0, 0

        async def run():
            return await asyncio.gather(*(cls.deliver(d) for d in deliveries))

        results = asyncio.run(run())
        delivered = sum(1 for ok in results if ok)
        return delivered, len(results) - delivered
