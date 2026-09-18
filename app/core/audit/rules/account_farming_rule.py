from datetime import timedelta
from django.utils import timezone
from asgiref.sync import sync_to_async
from devkit.message import Message
from core.models import DeviceAccountLink
from core.audit.events import ClientEvent, TransactionEvent

from .base_rule import BaseRule
from .mule_thresholds import get_mule_thresholds


class AccountFarmingRule(BaseRule):
    """
    Flags a device that is creating accounts in bulk.

    MultiAccountingRule counts accounts a device has ever used, which a
    shared family laptop trips honestly. This counts accounts *first seen* on
    the device within a day, which is what an account farm looks like.
    """

    @property
    def applies(self):
        return (
            isinstance(self.event, (ClientEvent, TransactionEvent))
            and self.scope.device_identity is not None
        )

    async def perform(self):
        thresholds = get_mule_thresholds(self.policy)
        limit = thresholds["new_accounts_per_device_per_day"]
        since = timezone.now() - timedelta(days=1)

        count = await sync_to_async(
            DeviceAccountLink.objects.filter(
                device=self.scope.device_identity,
                application=self.application,
                first_seen_at__gte=since,
            ).count
        )()

        if count <= limit:
            return None

        return Message(
            code="account_farming",
            path="visit_id",
            text=f"{count} accounts were first seen on this device within a day",
            context=dict(
                new_accounts=count,
                limit=limit,
                device_id=str(self.scope.device_identity.id),
                score=min(0.7 + 0.05 * (count - limit), 0.95),
            ),
        )
