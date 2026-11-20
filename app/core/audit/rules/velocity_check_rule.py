from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Q
from devkit.message import Message
from core.audit.events import TransactionEvent
from core.audit.rules.base_rule import BaseRule
from core.audit.lock_cache import lockcache, LockCache
from .base_rule import Maturity, RuleKind


class VelocityCheckRule(BaseRule, LockCache):

    techniques = ("T1110",)
    kind = RuleKind.DETECTION
    maturity = Maturity.PROPOSED

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

    # Share of the hourly limit, seen within five minutes, that counts as
    # pacing toward it.
    PACE_SHARE = 0.5

    @property
    def applies(self):
        return isinstance(self.event, TransactionEvent)

    @lockcache(key="velocity_data")
    async def get_velocity_data(self):
        """
        Every window's counts from one query over the account's last day.

        This used to be sixteen queries, four counts for each of four windows,
        and it was the slowest rule in the engine: each one a round trip, and
        the rules' database work shares a thread. Conditional aggregation
        reads the same rows once.
        """
        from asgiref.sync import sync_to_async
        from core.audit.models import AuditLog, AuditLogCategory

        client_id = self.event.account_id
        if not client_id:
            return None

        now = timezone.now()
        since = {name: now - delta for name, delta in self.VELOCITY_WINDOWS.items()}
        widest = min(since.values())

        aggregates = {}
        for name, start in since.items():
            within = Q(timestamp__gte=start)
            aggregates[f"{name}__transaction_count"] = Count("id", filter=within)
            aggregates[f"{name}__failed_count"] = Count("id", filter=within & Q(outcome="failure"))
            # A missing device or address is not one more of them.
            aggregates[f"{name}__unique_devices"] = Count("device_fingerprint", filter=within, distinct=True)
            aggregates[f"{name}__unique_ips"] = Count("ip_address", filter=within, distinct=True)

        @sync_to_async
        def fetch():
            return AuditLog.objects.filter(
                application_id=self.application.id,
                category=AuditLogCategory.TRANSACTION,
                actor_id=client_id,
                timestamp__gte=widest,
            ).aggregate(**aggregates)

        totals = await fetch()

        return {
            name: {
                measure: totals[f"{name}__{measure}"] or 0
                for measure in ("transaction_count", "failed_count", "unique_devices", "unique_ips")
            }
            for name in self.VELOCITY_WINDOWS
        }

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

        # The pace, before the ceiling. Half the hourly allowance inside five
        # minutes will hit the limit in ten; saying so now is cheaper than
        # saying it then.
        hourly_limit = thresholds["transactions_per_hour"]
        five_minute_count = five_min_data.get("transaction_count", 0)
        if (
            hourly_limit > 0
            and five_minute_count >= max(3, hourly_limit * self.PACE_SHARE)
            and hour_data.get("transaction_count", 0) <= hourly_limit
        ):
            messages.append(Message(
                code="velocity_pace",
                path="transaction",
                context={
                    "count_5_minutes": five_minute_count,
                    "hourly_limit": hourly_limit,
                    "share_of_hourly_limit": round(five_minute_count / hourly_limit, 2),
                    "window": "5 minutes",
                },
                text="Transaction pace would exceed the hourly limit within minutes",
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
