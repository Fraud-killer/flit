from devkit.message import Message
from core.intelligence import email_intelligence

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class DisposableEmailRule(BaseRule):
    """
    Flags an address at a throwaway or reserved domain.

    A disposable inbox is how bulk signup survives email verification: the
    script reads the confirmation itself, so `email_verified` stops meaning
    a human was present. Treating the domain as a signal is what puts that
    back.
    """

    techniques = ("T1585",)
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_signup_defence.py::TestSeptember2026Replay"

    @property
    def applies(self):
        return event_value(self.event, "email") is not None

    async def perform(self):
        analysis = email_intelligence.analyze(event_value(self.event, "email"))

        if not analysis.valid:
            return None

        if analysis.is_reserved:
            return Message(
                code="reserved_email_domain",
                path="email",
                text=f"{analysis.domain} is reserved for testing and cannot receive mail",
                context=dict(severity=0.9, **analysis.context),
            )

        if analysis.is_disposable:
            return Message(
                code="disposable_email_domain",
                path="email",
                text=f"{analysis.domain} hands out throwaway inboxes",
                context=dict(severity=0.85, **analysis.context),
            )

        return None
