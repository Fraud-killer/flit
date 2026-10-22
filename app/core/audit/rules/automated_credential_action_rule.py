from devkit.message import Message

from core.audit.events import AuthenticationEvent
from core.intelligence.bot_detection import BotDetector
from core.intelligence.ip_intelligence import IPIntelligence

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import fetch_visit_signals, event_value


class AutomatedCredentialActionRule(BaseRule):
    """
    A credential action — login, reset, second factor off, contact change —
    performed by a script.

    Bot and IP reputation each already flag their half of this. What neither
    says is what the script was *doing*. A crawler on a product page is
    noise; `python-requests` from a hosting provider completing a password
    reset is the whole attack in one line. The action is what makes the
    automation evidence, so this rule reads both together and grades by how
    much of the actor is machine: a bare HTTP client alone is strong, a bare
    HTTP client on a datacenter IP is as strong as the signal gets.

    A person on a VPN with a normal browser does not trip this. The
    datacenter origin only raises a finding that the user agent started.
    """

    techniques = ("F1002", "F1006")
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_credential_takeover.py::TestOctober2026Replay"

    @property
    def applies(self):
        return (
            isinstance(self.event, AuthenticationEvent)
            and self.event.is_credential_action
            and (
                event_value(self.event, "user_agent") is not None
                or event_value(self.event, "visit_id") is not None
            )
        )

    async def perform(self):
        visit = await fetch_visit_signals(self)

        user_agent = event_value(self.event, "user_agent") or getattr(visit, "user_agent", None)
        if not user_agent:
            return None

        bot = BotDetector.detect(user_agent)
        fingerprint_bad = getattr(visit, "bot", None) == "bad"

        if not (bot.is_bot and not BotDetector.is_allowed_bot(bot)) and not fingerprint_bad:
            return None

        ip_address = event_value(self.event, "ip_address") or getattr(visit, "ip", None)
        datacenter = bool(getattr(visit, "is_datacenter", None))
        asn_org = getattr(visit, "asn_org", None)

        if ip_address:
            info = await IPIntelligence.analyze(ip_address)
            datacenter = datacenter or info.is_datacenter
            asn_org = asn_org or info.asn_org

        severity = 0.75
        if datacenter:
            severity = 1.0
        elif getattr(self.event, "second_factor", None) is True:
            # A script clearing a second factor had the secret, not a guess.
            severity = 0.9

        origin = f"{bot.bot_type or 'automated client'}"
        if datacenter:
            origin += f" on a hosting provider ({asn_org})" if asn_org else " on a hosting provider"

        return Message(
            code="automated_credential_action",
            path="user_agent",
            text=f"{self.event.action} performed by {origin}",
            context=dict(
                severity=severity,
                action=self.event.action,
                bot_type=bot.bot_type,
                bot_signals=bot.signals,
                datacenter=datacenter,
                asn_org=asn_org,
                ip_address=ip_address,
                second_factor=event_value(self.event, "second_factor"),
                user_agent=user_agent[:200],
            ),
        )
