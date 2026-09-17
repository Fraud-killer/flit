from devkit import undefined
from devkit.message import Message
from core.audit.events import TransactionEvent

from .base_rule import BaseRule


SEVERITY_SCORES = {
    "low": 0.3,
    "medium": 0.5,
    "high": 0.75,
    "critical": 0.95,
}


class PaymentRule(BaseRule):
    """
    Base for rules that analyse the raw payment payload a merchant sends
    alongside a transaction (billing, gateway_message, card_fingerprint...).

    Those fields are not declared TransactionEvent attributes, so they land
    in `event.extra`; `payload` merges them with the declared attributes into
    the flat dict the payment rules were written against.

    Subclasses either implement `analyze(payload)` and call `add_message`,
    or override `perform` and return messages built with `signal`.
    """

    # The rule applies when any of these payload fields is present.
    trigger_fields = ()

    @property
    def applies(self):
        payload = self.payload
        return (
            isinstance(self.event, TransactionEvent)
            and any(payload.get(name) not in (None, "", undefined) for name in self.trigger_fields)
        )

    @property
    def payload(self):
        payload = dict(self.event.extra)

        for name in self.event.attributes:
            value = getattr(self.event, name, undefined)
            if value is not undefined and value is not None:
                payload.setdefault(name, value)

        if "customer_id" not in payload and "client_id" in payload:
            payload["customer_id"] = payload["client_id"]

        request_details = payload.get("request_details")
        if "ip_address" not in payload and isinstance(request_details, dict):
            if request_details.get("ipAddress"):
                payload["ip_address"] = request_details["ipAddress"]

        return payload

    def signal(self, code, text, score, **context):
        return Message(code=code, text=text, context=dict(score=score, **context))

    def add_message(self, text, severity="medium", code=None):
        self.messages.append(
            self.signal(
                code or self.default_code,
                text,
                SEVERITY_SCORES.get(severity, 0.5),
                severity=severity,
            )
        )

    @property
    def default_code(self):
        return type(self).__name__

    async def analyze(self, payload):
        raise NotImplementedError

    async def perform(self):
        self.messages = []
        await self.analyze(self.payload)
        return self.messages
