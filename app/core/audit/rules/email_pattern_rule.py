from devkit.message import Message
from core.intelligence import email_intelligence

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class EmailPatternRule(BaseRule):
    """
    Flags an address whose local part was generated rather than chosen.

    Bulk signup scripts name accounts after the clock. Two addresses in a real
    September 2026 flood were `figomass1789844680` and `figomass1789844685` —
    unix epochs five seconds apart. A person picking an address does not do
    that, so an embedded timestamp is close to a free, precise signal.

    The plus-tag finding is reported but barely scored: a tagged address is
    ordinary hygiene for real users. Its value is in the identity ladder,
    where the tag is collapsed so several tagged signups resolve to one
    mailbox and AccountFarmingRule can count them.
    """

    techniques = ("T1585",)
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_signup_defence.py::TestEmailIntelligence"

    @property
    def applies(self):
        return event_value(self.event, "email") is not None

    async def perform(self):
        analysis = email_intelligence.analyze(event_value(self.event, "email"))

        if not analysis.valid:
            return None

        messages = []

        if analysis.has_epoch_local:
            messages.append(
                Message(
                    code="generated_email_local_part",
                    path="email",
                    text=(
                        "The address embeds a unix timestamp "
                        f"({analysis.epoch_at.isoformat()}), so it was generated"
                    ),
                    context=dict(severity=0.9, **analysis.context),
                )
            )
        elif analysis.digit_ratio >= 0.5 and len(analysis.local) >= 10:
            messages.append(
                Message(
                    code="generated_email_local_part",
                    path="email",
                    text="The address is mostly digits, which suggests it was generated",
                    context=dict(severity=0.6, **analysis.context),
                )
            )

        if analysis.is_adversarial:
            messages.append(
                Message(
                    code="adversarial_email_local_part",
                    path="email",
                    text="The address names a security testing tool or programme",
                    context=dict(severity=0.7, **analysis.context),
                )
            )

        if analysis.has_plus_tag:
            messages.append(
                Message(
                    code="plus_tagged_email",
                    path="email",
                    text=(
                        f"Address is plus-tagged (+{analysis.plus_tag}); it shares a "
                        "mailbox with any other tag on the same root"
                    ),
                    context=dict(severity=0.3, **analysis.context),
                )
            )

        return messages
