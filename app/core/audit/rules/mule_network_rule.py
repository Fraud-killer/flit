from asgiref.sync import sync_to_async
from devkit.message import Message
from core.models import AuditLog, DeviceAccountLink
from core.audit.models import AuditLogLabel
from core.audit.events import ClientEvent, TransactionEvent

from .base_rule import BaseRule
from .mule_thresholds import get_mule_thresholds


FRAUD_LABELS = [AuditLogLabel.FRAUD, AuditLogLabel.CHARGEBACK]


class MuleNetworkRule(BaseRule):
    """
    Flags an account sharing a device with accounts already confirmed
    fraudulent.

    This is what the graph plus reported outcomes buy that a single
    transaction never shows: mules work in sets, and once one is confirmed,
    the rest of the set is visible.
    """

    @property
    def applies(self):
        return (
            isinstance(self.event, (ClientEvent, TransactionEvent))
            and self.event.account_id is not None
            and self.scope.device_identity is not None
        )

    async def perform(self):
        thresholds = get_mule_thresholds(self.policy)
        limit = thresholds["confirmed_fraud_accounts_per_device"]

        known = await sync_to_async(self.confirmed_fraud_accounts)()

        if len(known) < limit:
            return None

        return Message(
            code="mule_network_device",
            path="client_id",
            text=(
                f"Device is shared with {len(known)} account(s) already "
                f"confirmed as fraudulent"
            ),
            context=dict(
                accounts=len(known),
                device_id=str(self.scope.device_identity.id),
                score=min(0.8 + 0.05 * len(known), 0.95),
            ),
        )

    def confirmed_fraud_accounts(self):
        """Other accounts on this device with a fraud label against them."""
        siblings = set(
            DeviceAccountLink.objects
            .filter(device=self.scope.device_identity, application=self.application)
            .exclude(client_id=self.event.account_id)
            .values_list("client_id", flat=True)
        )

        if not siblings:
            return set()

        return set(
            AuditLog.objects
            .filter(
                application_id=self.application.id,
                actor_id__in=siblings,
                label__in=FRAUD_LABELS,
            )
            .values_list("actor_id", flat=True)
            .distinct()
        )
