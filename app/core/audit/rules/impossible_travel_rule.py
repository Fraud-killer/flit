import math
from datetime import timedelta
from django.utils import timezone
from devkit.message import Message
from core.audit.events import TransactionEvent
from core.audit.rules.base_rule import BaseRule
from core.audit.lock_cache import lockcache, LockCache


class ImpossibleTravelRule(BaseRule, LockCache):
    MAX_TRAVEL_SPEED_KMH = 900
    MIN_TIME_BETWEEN_EVENTS_SECONDS = 60

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and hasattr(self.event, "latitude")
            and hasattr(self.event, "longitude")
            and self.event.latitude is not None
            and self.event.longitude is not None
        )

    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    @lockcache(key="previous_locations")
    async def get_previous_locations(self):
        from asgiref.sync import sync_to_async
        from core.audit.models import AuditLog, AuditLogCategory

        client_id = getattr(self.event, "client_id", None)
        device_fingerprint = getattr(self.event, "device_fingerprint", None)

        if not client_id and not device_fingerprint:
            return []

        lookback_hours = getattr(self.policy, "impossible_travel_lookback_hours", 24)
        lookback_time = timezone.now() - timedelta(hours=lookback_hours)

        @sync_to_async
        def fetch_locations():
            query = AuditLog.objects.filter(
                application_id=self.application.id,
                category=AuditLogCategory.TRANSACTION,
                timestamp__gte=lookback_time,
            ).exclude(
                context__latitude__isnull=True,
            ).order_by("-timestamp")

            if client_id:
                query = query.filter(actor_id=client_id)

            locations = []
            for log in query[:20]:
                context = log.context or {}
                if "latitude" in context and "longitude" in context:
                    locations.append({
                        "timestamp": log.timestamp,
                        "latitude": context["latitude"],
                        "longitude": context["longitude"],
                        "city": context.get("city"),
                        "country": context.get("country"),
                        "ip_address": log.ip_address,
                    })

            return locations

        return await fetch_locations()

    def calculate_required_speed(
        self,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
        time_diff_seconds: float,
    ) -> float:
        if time_diff_seconds < self.MIN_TIME_BETWEEN_EVENTS_SECONDS:
            return float("inf")

        distance_km = self.haversine_distance(lat1, lon1, lat2, lon2)
        time_hours = time_diff_seconds / 3600

        return distance_km / time_hours if time_hours > 0 else float("inf")

    async def perform(self):
        current_lat = self.event.latitude
        current_lon = self.event.longitude
        current_time = timezone.now()

        previous_locations = await self.get_previous_locations()

        if not previous_locations:
            return None

        messages = []
        max_speed = getattr(self.policy, "max_travel_speed_kmh", self.MAX_TRAVEL_SPEED_KMH)

        for prev_location in previous_locations:
            prev_lat = prev_location["latitude"]
            prev_lon = prev_location["longitude"]
            prev_time = prev_location["timestamp"]

            time_diff = (current_time - prev_time).total_seconds()

            if time_diff < self.MIN_TIME_BETWEEN_EVENTS_SECONDS:
                continue

            required_speed = self.calculate_required_speed(
                prev_lat, prev_lon, current_lat, current_lon, time_diff
            )

            distance_km = self.haversine_distance(prev_lat, prev_lon, current_lat, current_lon)

            if distance_km < 50:
                continue

            if required_speed > max_speed:
                time_diff_minutes = int(time_diff / 60)

                messages.append(Message(
                    code="impossible_travel_detected",
                    path="location",
                    context={
                        "current_location": {
                            "latitude": current_lat,
                            "longitude": current_lon,
                        },
                        "previous_location": {
                            "latitude": prev_lat,
                            "longitude": prev_lon,
                            "city": prev_location.get("city"),
                            "country": prev_location.get("country"),
                        },
                        "distance_km": round(distance_km, 2),
                        "time_diff_minutes": time_diff_minutes,
                        "required_speed_kmh": round(required_speed, 2),
                        "max_allowed_speed_kmh": max_speed,
                    },
                    text=f"Impossible travel detected: {round(distance_km)}km in {time_diff_minutes} minutes requires {round(required_speed)}km/h",
                ))

                break

        return messages if messages else None


class AccountTakeoverRule(BaseRule, LockCache):
    @property
    def applies(self):
        return isinstance(self.event, TransactionEvent)

    @lockcache(key="account_signals")
    async def get_account_signals(self):
        from asgiref.sync import sync_to_async
        from core.audit.models import AuditLog, AuditLogCategory

        client_id = getattr(self.event, "client_id", None)
        if not client_id:
            return None

        lookback_time = timezone.now() - timedelta(hours=24)

        @sync_to_async
        def fetch_signals():
            recent_logs = AuditLog.objects.filter(
                application_id=self.application.id,
                actor_id=client_id,
                timestamp__gte=lookback_time,
            )

            signals = {
                "password_changes": recent_logs.filter(action="password_change").count(),
                "email_changes": recent_logs.filter(action="email_change").count(),
                "phone_changes": recent_logs.filter(action="phone_change").count(),
                "new_device_logins": recent_logs.filter(action="new_device_login").count(),
                "failed_logins": recent_logs.filter(
                    category=AuditLogCategory.AUTHENTICATION,
                    outcome="failure",
                ).count(),
                "high_value_transactions": recent_logs.filter(
                    category=AuditLogCategory.TRANSACTION,
                    context__is_high_value=True,
                ).count(),
            }

            return signals

        return await fetch_signals()

    async def perform(self):
        signals = await self.get_account_signals()

        if signals is None:
            return None

        messages = []
        risk_indicators = 0

        if signals["password_changes"] > 0:
            risk_indicators += 2

        if signals["email_changes"] > 0:
            risk_indicators += 2

        if signals["new_device_logins"] > 0:
            risk_indicators += 1

        if signals["failed_logins"] >= 3:
            risk_indicators += 1

        is_high_value = getattr(self.event, "is_high_value", False)
        if is_high_value:
            risk_indicators += 1

        if risk_indicators >= 3:
            messages.append(Message(
                code="account_takeover_risk",
                path="account",
                context={
                    "signals": signals,
                    "risk_indicators": risk_indicators,
                },
                text="High risk of account takeover: multiple suspicious signals detected",
            ))

        return messages if messages else None
