from datetime import timedelta
from django.utils import timezone
from asgiref.sync import sync_to_async
from devkit.message import Message
from core.models import DeviceAccountLink
from core.audit.events import ClientEvent, TransactionEvent

from .base_rule import BaseRule
from .device_thresholds import get_device_thresholds, scaled_score


class MultiAccountingRule(BaseRule):
    """Flags a device used by more accounts than the policy allows."""

    @property
    def applies(self):
        return (
            isinstance(self.event, (ClientEvent, TransactionEvent))
            and self.scope.device_identity is not None
        )

    async def perform(self):
        thresholds = get_device_thresholds(self.policy)
        limit = thresholds["max_accounts_per_device"]
        window_days = thresholds["accounts_per_device_window_days"]
        since = timezone.now() - timedelta(days=window_days)

        count = await sync_to_async(
            DeviceAccountLink.objects.filter(
                device=self.scope.device_identity,
                application=self.application,
                last_seen_at__gte=since,
            ).count
        )()

        if count <= limit:
            return None

        return Message(
            code="multi_accounting",
            path="visit_id",
            text=f"Device used by {count} accounts in {window_days} days",
            context=dict(
                accounts=count,
                limit=limit,
                window_days=window_days,
                device_id=str(self.scope.device_identity.id),
                score=scaled_score(count, limit, base=0.6),
            ),
        )
