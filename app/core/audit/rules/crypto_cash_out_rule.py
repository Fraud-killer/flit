from devkit.message import Message
from core.audit.events import TransactionEvent

from .base_rule import BaseRule, Maturity, RuleKind
from .crypto_thresholds import get_crypto_thresholds
from .visit_signals import event_value


class CryptoCashOutRule(BaseRule):
    """
    Flags value that arrived and left again on a chain, quickly.

    F3 calls this Convert to Cryptocurrency, and it is the exit that makes
    the rest of the fraud worth committing: a chain withdrawal clears in
    minutes and cannot be recalled, so the window between money arriving and
    money being gone is the whole opportunity to act.

    PassThroughRule sees the same shape without knowing the rail. This rule
    exists because the rail is what decides how much time there is — a card
    chargeback can be fought for months, an on-chain transfer for nothing.
    """

    techniques = ("F1018",)
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_crypto.py::TestCryptoCashOut"

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and event_value(self.event, "chain") is not None
            and self.scope.account_activity is not None
        )

    async def perform(self):
        activity = self.scope.account_activity
        thresholds = get_crypto_thresholds(self.policy)

        if event_value(self.event, "type") != "debit":
            return None

        amount = event_value(self.event, "amount")
        if not amount:
            return None

        minutes = thresholds["cash_out_minutes"]
        credits = activity.within(minutes=minutes, kind="credit")

        if not credits:
            return None

        received = activity.total(credits)
        if not received:
            return None

        ratio = float(amount) / received

        if ratio < thresholds["cash_out_ratio"]:
            return None

        return Message(
            code="crypto_cash_out",
            path="amount",
            text=(
                f"{round(ratio * 100)}% of funds received in the last "
                f"{minutes} minutes is leaving on "
                f"{event_value(self.event, 'chain')}"
            ),
            context=dict(
                ratio=round(ratio, 3),
                window_minutes=minutes,
                received=received,
                chain=event_value(self.event, "chain"),
                asset=event_value(self.event, "asset"),
                severity=round(min(0.6 + 0.3 * (ratio - thresholds["cash_out_ratio"]), 0.9), 4),
            ),
        )
