from devkit.message import Message
from core.audit.events import ClientEvent, TransactionEvent
from core.intelligence.bot_detection import BotDetector

from .base_rule import BaseRule
from .visit_signals import fetch_visit_signals, event_value


class BotSignalRule(BaseRule):
    """
    Flags automated clients using the event's `user_agent` and Fingerprint
    bot detection for its `visit_id`. Known good crawlers are not flagged.
    """

    @property
    def applies(self):
        return isinstance(self.event, (ClientEvent, TransactionEvent)) and (
            event_value(self.event, "user_agent") is not None
            or event_value(self.event, "visit_id") is not None
        )

    async def perform(self):
        visit = await fetch_visit_signals(self)
        messages = []

        if getattr(visit, "bot", None) == "bad":
            messages.append(
                Message(
                    code="bot_detected:fingerprint",
                    path="visit_id",
                    text="Fingerprint bot detection flagged this visit as a bad bot",
                    context=dict(score=0.9, source="fingerprint"),
                )
            )

        user_agent = event_value(self.event, "user_agent") or getattr(visit, "user_agent", None)
        if not user_agent:
            return messages

        result = BotDetector.detect(user_agent)

        if result.is_bot and not BotDetector.is_allowed_bot(result):
            messages.append(
                Message(
                    code=f"bot_detected:{result.bot_type}",
                    path="user_agent",
                    text=f"User agent looks automated ({result.bot_type})",
                    context=dict(
                        score=result.confidence,
                        signals=result.signals,
                        user_agent=user_agent[:200],
                        source="user_agent",
                    ),
                )
            )

        return messages
