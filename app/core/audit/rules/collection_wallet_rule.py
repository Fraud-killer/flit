from datetime import timedelta

from asgiref.sync import sync_to_async
from django.utils import timezone
from devkit.message import Message

from core.audit.events import TransactionEvent
from core.models.identity import IdentityAccountLink

from .base_rule import BaseRule, Maturity, RuleKind
from .crypto_thresholds import get_crypto_thresholds
from .visit_signals import event_value


@sync_to_async
def _accounts_paying(identity_key, application, since):
    return (
        IdentityAccountLink.objects
        .filter(
            identity_key=identity_key,
            application=application,
            last_seen_at__gte=since,
        )
        .values("client_id")
        .distinct()
        .count()
    )


class CollectionWalletRule(BaseRule):
    """
    Flags many accounts paying into one address.

    This is mule collection seen from the receiving end: a ring opens
    accounts, funds them however it can and sweeps everything to one wallet.
    The accounts look unrelated — different devices, different addresses,
    different countries — and the destination is the only thing they share.

    The destination is never treated as identity, only counted. An exchange
    deposit address, a payroll wallet or a merchant's till legitimately
    receives from thousands of unrelated people, which is why the limit is
    generous and why this rule names the address rather than the senders.
    """

    techniques = ("F1047",)
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_crypto.py::TestCollectionWallet"

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and self.scope.identity_ladder is not None
            and self.scope.identity_ladder.counterparty_key is not None
        )

    async def perform(self):
        thresholds = get_crypto_thresholds(self.policy)
        limit = thresholds["accounts_per_destination"]
        window = thresholds["destination_window_days"]

        key = self.scope.identity_ladder.counterparty_key

        count = await _accounts_paying(
            key, self.application, timezone.now() - timedelta(days=window),
        )

        if count <= limit:
            return None

        return Message(
            code="collection_wallet",
            path="counterparty_address",
            text=(
                f"{count} accounts have paid into this address in "
                f"{window} days"
            ),
            context=dict(
                accounts=count,
                limit=limit,
                window_days=window,
                address=key.preview,
                chain=event_value(self.event, "chain"),
                severity=round(min(0.6 + 0.05 * (count - limit), 0.95), 4),
            ),
        )
