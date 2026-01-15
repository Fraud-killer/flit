from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Sum
from devkit.message import Message
from core.audit.events import TransactionEvent
from core.audit.rules.base_rule import BaseRule
from core.audit.lock_cache import lockcache, LockCache


class VelocityCheckRule(BaseRule, LockCache):
    VELOCITY_WINDOWS = {
        "1_minute": timedelta(minutes=1),
        "5_minutes": timedelta(minutes=5),
        "1_hour": timedelta(hours=1),
        "24_hours": timedelta(hours=24),
    }

    DEFAULT_THRESHOLDS = {
        "transactions_per_minute": 5,
        "transactions_per_5_minutes": 15,
        "transactions_per_hour": 50,
        "transactions_per_day": 200,
        "unique_devices_per_hour": 3,
        "unique_ips_per_hour": 5,
        "failed_transactions_per_hour": 10,
    }

    @property
    def applies(self):
        return isinstance(self.event, TransactionEvent)

    @lockcache(key="velocity_data")
    async def get_velocity_data(self):
        from core.audit.models import AuditLog, AuditLogCategory

        now = timezone.now()
        client_id = getattr(self.event, "client_id", None)
        device_fingerprint = getattr(self.event, "device_fingerprint", None)

        if not client_id and not device_fingerprint:
            return None

        base_query = AuditLog.objects.filter(
            application_id=self.application.id,
            category=AuditLogCategory.TRANSACTION,
        )

        if client_id:
            base_query = base_query.filter(actor_id=client_id)

        velocity_data = {}

        for window_name, window_delta in self.VELOCITY_WINDOWS.items():
            window_start = now - window_delta
            window_query = base_query.filter(timestamp__gte=window_start)

            velocity_data[window_name] = {
                "transaction_count": await self._async_count(window_query),
                "failed_count": await self._async_count(
                    window_query.filter(outcome="failure")
                ),
                "unique_devices": await self._async_distinct_count(
                    window_query, "device_fingerprint"
                ),
                "unique_ips": await self._async_distinct_count(
                    window_query, "ip_address"
                ),
            }

        return velocity_data

    async def _async_count(self, queryset):
        from asgiref.sync import sync_to_async
        return await sync_to_async(queryset.count)()

    async def _async_distinct_count(self, queryset, field):
        from asgiref.sync import sync_to_async

        @sync_to_async
        def get_count():
            return queryset.values(field).distinct().count()

        return await get_count()

    def get_thresholds(self):
        policy_thresholds = getattr(self.policy, "velocity_thresholds", None)
        if policy_thresholds:
            return {**self.DEFAULT_THRESHOLDS, **policy_thresholds}
        return self.DEFAULT_THRESHOLDS

    async def perform(self):
        velocity_data = await self.get_velocity_data()

        if velocity_data is None:
            return None

        thresholds = self.get_thresholds()
        messages = []

        minute_data = velocity_data.get("1_minute", {})
        if minute_data.get("transaction_count", 0) > thresholds["transactions_per_minute"]:
            messages.append(Message(
                code="velocity_exceeded_per_minute",
                path="transaction",
                context={
                    "count": minute_data["transaction_count"],
                    "threshold": thresholds["transactions_per_minute"],
                    "window": "1 minute",
                },
                text="Transaction velocity exceeded: too many transactions per minute",
            ))

        five_min_data = velocity_data.get("5_minutes", {})
        if five_min_data.get("transaction_count", 0) > thresholds["transactions_per_5_minutes"]:
            messages.append(Message(
                code="velocity_exceeded_per_5_minutes",
                path="transaction",
                context={
                    "count": five_min_data["transaction_count"],
                    "threshold": thresholds["transactions_per_5_minutes"],
                    "window": "5 minutes",
                },
                text="Transaction velocity exceeded: too many transactions in 5 minutes",
            ))

        hour_data = velocity_data.get("1_hour", {})
        if hour_data.get("transaction_count", 0) > thresholds["transactions_per_hour"]:
            messages.append(Message(
                code="velocity_exceeded_per_hour",
                path="transaction",
                context={
                    "count": hour_data["transaction_count"],
                    "threshold": thresholds["transactions_per_hour"],
                    "window": "1 hour",
                },
                text="Transaction velocity exceeded: too many transactions per hour",
            ))

        if hour_data.get("unique_devices", 0) > thresholds["unique_devices_per_hour"]:
            messages.append(Message(
                code="multiple_devices_detected",
                path="device",
                context={
                    "count": hour_data["unique_devices"],
                    "threshold": thresholds["unique_devices_per_hour"],
                    "window": "1 hour",
                },
                text="Multiple devices detected for this account in short time period",
            ))

        if hour_data.get("unique_ips", 0) > thresholds["unique_ips_per_hour"]:
            messages.append(Message(
                code="multiple_ips_detected",
                path="ip_address",
                context={
                    "count": hour_data["unique_ips"],
                    "threshold": thresholds["unique_ips_per_hour"],
                    "window": "1 hour",
                },
                text="Multiple IP addresses detected for this account in short time period",
            ))

        if hour_data.get("failed_count", 0) > thresholds["failed_transactions_per_hour"]:
            messages.append(Message(
                code="high_failure_rate",
                path="transaction",
                context={
                    "failed_count": hour_data["failed_count"],
                    "threshold": thresholds["failed_transactions_per_hour"],
                    "window": "1 hour",
                },
                text="High transaction failure rate detected",
            ))

        day_data = velocity_data.get("24_hours", {})
        if day_data.get("transaction_count", 0) > thresholds["transactions_per_day"]:
            messages.append(Message(
                code="velocity_exceeded_per_day",
                path="transaction",
                context={
                    "count": day_data["transaction_count"],
                    "threshold": thresholds["transactions_per_day"],
                    "window": "24 hours",
                },
                text="Transaction velocity exceeded: too many transactions per day",
            ))

        return messages if messages else None
