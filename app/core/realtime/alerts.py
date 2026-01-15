import json
import logging
from enum import Enum
from uuid import UUID, uuid4
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


logger = logging.getLogger(__name__)


class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertCategory(str, Enum):
    FRAUD = "fraud"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    SYSTEM = "system"
    TRANSACTION = "transaction"
    DEVICE = "device"
    ACCOUNT = "account"


@dataclass
class Alert:
    id: str = field(default_factory=lambda: str(uuid4()))
    level: AlertLevel = AlertLevel.WARNING
    category: AlertCategory = AlertCategory.SECURITY
    title: str = ""
    message: str = ""
    application_id: Optional[str] = None
    organization_id: Optional[str] = None
    actor_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    risk_score: Optional[float] = None
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: timezone.now().isoformat())
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["level"] = self.level.value
        data["category"] = self.category.value
        return data


class AlertManager:
    CHANNEL_PREFIX = "alerts"

    @classmethod
    def get_channel_name(cls, application_id: Optional[str] = None) -> str:
        if application_id:
            return f"{cls.CHANNEL_PREFIX}_{application_id}"
        return f"{cls.CHANNEL_PREFIX}_global"

    @classmethod
    def get_organization_channel(cls, organization_id: str) -> str:
        return f"{cls.CHANNEL_PREFIX}_org_{organization_id}"

    @classmethod
    async def send_alert(cls, alert: Alert) -> None:
        channel_layer = get_channel_layer()
        if not channel_layer:
            logger.warning("No channel layer configured, alert not sent")
            return

        alert_data = alert.to_dict()

        channels_to_notify = [cls.get_channel_name()]

        if alert.application_id:
            channels_to_notify.append(cls.get_channel_name(alert.application_id))

        if alert.organization_id:
            channels_to_notify.append(cls.get_organization_channel(alert.organization_id))

        for channel in channels_to_notify:
            try:
                await channel_layer.group_send(
                    channel,
                    {
                        "type": "alert.message",
                        "alert": alert_data,
                    }
                )
            except Exception as e:
                logger.error(f"Failed to send alert to {channel}: {e}")

    @classmethod
    def send_alert_sync(cls, alert: Alert) -> None:
        async_to_sync(cls.send_alert)(alert)

    @classmethod
    def create_fraud_alert(
        cls,
        title: str,
        message: str,
        *,
        application_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        risk_score: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        level = AlertLevel.WARNING
        if risk_score:
            if risk_score >= 0.8:
                level = AlertLevel.CRITICAL
            elif risk_score >= 0.9:
                level = AlertLevel.EMERGENCY

        return Alert(
            level=level,
            category=AlertCategory.FRAUD,
            title=title,
            message=message,
            application_id=application_id,
            organization_id=organization_id,
            actor_id=actor_id,
            risk_score=risk_score,
            context=context or {},
        )

    @classmethod
    def create_security_alert(
        cls,
        title: str,
        message: str,
        *,
        level: AlertLevel = AlertLevel.WARNING,
        application_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        return Alert(
            level=level,
            category=AlertCategory.SECURITY,
            title=title,
            message=message,
            application_id=application_id,
            context=context or {},
        )

    @classmethod
    def create_transaction_alert(
        cls,
        title: str,
        message: str,
        *,
        application_id: str,
        actor_id: str,
        risk_score: float,
        transaction_id: Optional[str] = None,
        amount: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        alert_context = context or {}
        if transaction_id:
            alert_context["transaction_id"] = transaction_id
        if amount:
            alert_context["amount"] = amount

        level = AlertLevel.INFO
        if risk_score >= 0.5:
            level = AlertLevel.WARNING
        if risk_score >= 0.7:
            level = AlertLevel.CRITICAL
        if risk_score >= 0.9:
            level = AlertLevel.EMERGENCY

        return Alert(
            level=level,
            category=AlertCategory.TRANSACTION,
            title=title,
            message=message,
            application_id=application_id,
            actor_id=actor_id,
            resource_type="transaction",
            resource_id=transaction_id,
            risk_score=risk_score,
            context=alert_context,
        )

    @classmethod
    def create_impossible_travel_alert(
        cls,
        *,
        application_id: str,
        actor_id: str,
        current_location: Dict[str, Any],
        previous_location: Dict[str, Any],
        distance_km: float,
        time_diff_minutes: int,
    ) -> Alert:
        return Alert(
            level=AlertLevel.CRITICAL,
            category=AlertCategory.FRAUD,
            title="Impossible Travel Detected",
            message=f"User traveled {distance_km:.0f}km in {time_diff_minutes} minutes",
            application_id=application_id,
            actor_id=actor_id,
            risk_score=0.85,
            context={
                "current_location": current_location,
                "previous_location": previous_location,
                "distance_km": distance_km,
                "time_diff_minutes": time_diff_minutes,
            },
        )

    @classmethod
    def create_velocity_alert(
        cls,
        *,
        application_id: str,
        actor_id: str,
        velocity_type: str,
        count: int,
        threshold: int,
        window: str,
    ) -> Alert:
        return Alert(
            level=AlertLevel.WARNING,
            category=AlertCategory.FRAUD,
            title="Velocity Threshold Exceeded",
            message=f"{velocity_type}: {count} events in {window} (threshold: {threshold})",
            application_id=application_id,
            actor_id=actor_id,
            risk_score=0.6,
            context={
                "velocity_type": velocity_type,
                "count": count,
                "threshold": threshold,
                "window": window,
            },
        )

    @classmethod
    def create_account_takeover_alert(
        cls,
        *,
        application_id: str,
        actor_id: str,
        signals: Dict[str, int],
        risk_indicators: int,
    ) -> Alert:
        return Alert(
            level=AlertLevel.CRITICAL,
            category=AlertCategory.ACCOUNT,
            title="Account Takeover Risk Detected",
            message=f"Multiple suspicious signals detected ({risk_indicators} indicators)",
            application_id=application_id,
            actor_id=actor_id,
            risk_score=0.9,
            context={
                "signals": signals,
                "risk_indicators": risk_indicators,
            },
        )
