from django.utils import timezone
from asgiref.sync import sync_to_async
from devkit.message import Message
from core.models import DeviceAccountLink
from core.audit.events import ClientEvent, TransactionEvent

from .base_rule import BaseRule
from .device_thresholds import get_device_thresholds, scaled_score, DAY, HOUR


class AccountSharingRule(BaseRule):
    """
    Flags an account used from more devices than the policy allows: several
    within an hour suggests concurrent use (credential sharing or takeover),
    several within a day suggests account sharing.
    """

    @property
    def applies(self):
        return (
            isinstance(self.event, (ClientEvent, TransactionEvent))
            and self.event.account_id is not None
        )

    async def perform(self):
        thresholds = get_device_thresholds(self.policy)
        now = timezone.now()

        links = DeviceAccountLink.objects.filter(
            application=self.application,
            client_id=self.event.account_id,
        )

        hour_count, day_count = await sync_to_async(
            lambda: (
                links.filter(last_seen_at__gte=now - HOUR).count(),
                links.filter(last_seen_at__gte=now - DAY).count(),
            )
        )()

        hour_limit = thresholds["max_devices_per_account_per_hour"]
        day_limit = thresholds["max_devices_per_account_per_day"]

        if hour_count > hour_limit:
            return Message(
                code="concurrent_devices",
                path="client_id",
                text=f"Account used from {hour_count} devices within an hour",
                context=dict(
                    devices=hour_count,
                    limit=hour_limit,
                    window="1h",
                    score=scaled_score(hour_count, hour_limit, base=0.7),
                ),
            )

        if day_count > day_limit:
            return Message(
                code="account_sharing",
                path="client_id",
                text=f"Account used from {day_count} devices within a day",
                context=dict(
                    devices=day_count,
                    limit=day_limit,
                    window="24h",
                    score=scaled_score(day_count, day_limit),
                ),
            )

        return None
