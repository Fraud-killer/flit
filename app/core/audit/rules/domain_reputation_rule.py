from devkit.message import Message
from core.intelligence import email_intelligence
from core.intelligence.domain_intelligence import DomainIntelligence, NEW_DOMAIN_DAYS

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class DomainReputationRule(BaseRule):
    """
    Flags an address whose domain cannot receive mail, or barely exists yet.

    The local email heuristics catch domains someone has already listed. This
    catches the ones nobody has got to: a throwaway provider still has to
    publish MX records to work at all, and a domain registered to run one
    signup flood still carries its registration date.

    Both lookups are best effort. When neither can be established the rule
    says nothing, which is the honest answer — an unreachable resolver is not
    evidence of anything.
    """

    techniques = ("T1585", "T1583")
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = (
        "tests/unit/test_domain_intelligence.py::TestDomainReputationRule"
    )

    @property
    def applies(self):
        return event_value(self.event, "email") is not None

    async def perform(self):
        analysis = email_intelligence.analyze(event_value(self.event, "email"))

        if not analysis.valid:
            return None

        # A domain already flagged as disposable or reserved is reported by
        # its own rule; looking it up as well would score it twice.
        if analysis.is_disposable or analysis.is_reserved:
            return None

        info = await DomainIntelligence.analyze(analysis.domain)
        messages = []

        if info.cannot_receive_mail:
            messages.append(
                Message(
                    code="domain_cannot_receive_mail",
                    path="email",
                    text=f"{info.domain} publishes no MX records, so it cannot receive mail",
                    context=dict(severity=0.8, **info.as_context()),
                )
            )

        if info.is_newly_registered:
            messages.append(
                Message(
                    code="newly_registered_domain",
                    path="email",
                    text=(
                        f"{info.domain} was registered {info.age_days} days ago"
                        f" (under {NEW_DOMAIN_DAYS})"
                    ),
                    # A new domain is ordinary for a new business, so this is
                    # a nudge on its own and only bites alongside something
                    # else.
                    context=dict(severity=0.5, **info.as_context()),
                )
            )

        return messages
