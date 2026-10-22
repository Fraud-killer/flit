from devkit.message import Message
from core.audit.events import TransactionEvent
from core.intelligence import wallet_intelligence

from .base_rule import BaseRule, Maturity, RuleKind
from .crypto_thresholds import get_crypto_thresholds
from .visit_signals import event_value


class NewWithdrawalAddressRule(BaseRule):
    """
    Flags an account sending to a destination it has never used before.

    On its own this is unremarkable — people open new accounts elsewhere. It
    matters as a change of behaviour: an account that has withdrawn to the
    same address for months and suddenly pays a stranger is the signature of
    a takeover, and on a chain that transfer is final.

    So the rule deliberately stays silent for an account with little or no
    withdrawal history. A first withdrawal to a first address is just a first
    withdrawal, and flagging it would tax every new customer.
    """

    techniques = ("F1005",)
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_crypto.py::TestNewWithdrawalAddress"

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and event_value(self.event, "counterparty_address") is not None
            and self.scope.account_activity is not None
        )

    async def perform(self):
        activity = self.scope.account_activity
        thresholds = get_crypto_thresholds(self.policy)

        key = wallet_intelligence.address_key(
            event_value(self.event, "counterparty_address"),
            event_value(self.event, "chain"),
        )

        if not key:
            return None

        known = activity.withdrawal_addresses()

        if len(known) < thresholds["min_prior_withdrawals"]:
            return None

        if key in known:
            return None

        return Message(
            code="new_withdrawal_address",
            path="counterparty_address",
            text=(
                f"First withdrawal to this address; the account has used "
                f"{len(known)} others"
            ),
            context=dict(
                known_addresses=len(known),
                address=wallet_intelligence.redact(
                    event_value(self.event, "counterparty_address")
                ),
                chain=event_value(self.event, "chain"),
                severity=0.55,
            ),
        )
