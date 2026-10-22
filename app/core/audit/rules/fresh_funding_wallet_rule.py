from devkit.message import Message
from core.audit.events import TransactionEvent
from core.intelligence import wallet_intelligence
from core.intelligence.wallet_intelligence import WalletChainIntelligence

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class FreshFundingWalletRule(BaseRule):
    """
    Flags an account funded from a wallet that has never transacted.

    The same logic as a domain registered yesterday, and it works for the
    same reason: real users arrive with history. A wallet created minutes ago
    to pay for one signup has none, and a farm paying for fifty signups
    creates fifty such wallets.

    It asks a public node one question — has this address ever sent anything —
    and nothing else. No tracing, no clustering, no balances, no provenance:
    that is chain analytics, which is somebody else's product and which this
    rule deliberately does not attempt.

    **Which address.** The external one, which on a funding event is the
    counterparty. A platform that generates a deposit address per user is
    generating it itself, so its age says when the platform created it and it
    correlates nothing beyond the account it already belongs to. The address
    worth asking about is the one the money came from.

    Unknown is not evidence. A node that does not answer, a non-EVM chain and
    a disabled lookup all produce no finding rather than a guess.
    """

    techniques = ("T1583", "T1585")
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_wallet_history.py::TestFreshFundingWalletRule"

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and event_value(self.event, "type") == "credit"
            and self.external_address is not None
        )

    @property
    def external_address(self):
        """
        The counterparty on a funding event, falling back to a wallet the
        merchant has told us the account actually controls.
        """
        return (
            event_value(self.event, "counterparty_address")
            or event_value(self.event, "wallet_address")
        )

    async def perform(self):
        chain = event_value(self.event, "chain")
        history = await WalletChainIntelligence.analyze(self.external_address, chain)

        if not history.is_fresh:
            return None

        return Message(
            code="fresh_funding_wallet",
            path="counterparty_address",
            text="Funded from a wallet that has never sent a transaction",
            context=dict(
                address=wallet_intelligence.redact(self.external_address),
                chain=chain,
                # On its own a fresh wallet is thin: someone's first ever
                # transaction is somebody's genuine first transaction. It
                # earns its keep next to a farm or a bare HTTP client.
                severity=0.5,
                **history.as_context(),
            ),
        )
