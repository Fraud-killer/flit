from django.db.models import Count
from asgiref.sync import async_to_sync
from core.scoring import RiskEngine
from core.models import AuditLog, DeviceAccountLink


class DescribeDevice:
    """A device as one application sees it: its accounts, history and labels."""

    MAX_ACCOUNTS = 50
    MAX_RECENT_EVENTS = 20

    @classmethod
    def call(cls, *, device, application):
        links = DeviceAccountLink.objects.filter(device=device, application=application)

        audit_logs = AuditLog.objects.filter(
            application_id=application.id,
            device_fingerprint=device.external_id,
        )

        labels = dict(
            audit_logs.exclude(label=None)
            .values_list("label")
            .annotate(count=Count("id"))
        )

        trust_score = async_to_sync(RiskEngine().get_device_trust_score)(
            device_fingerprint=device.external_id,
            application_id=application.id,
        )

        return dict(
            id=str(device.id),
            source=device.source,
            external_id=device.external_id,
            flags=device.flags,
            trust_score=trust_score,
            last_country=device.last_country,
            last_ip_address=device.last_ip_address,
            first_seen_at=device.first_seen_at,
            last_seen_at=device.last_seen_at,
            account_count=links.count(),
            accounts=[
                dict(
                    client_id=link.client_id,
                    event_count=link.event_count,
                    first_seen_at=link.first_seen_at,
                    last_seen_at=link.last_seen_at,
                )
                for link in links.order_by("-last_seen_at")[:cls.MAX_ACCOUNTS]
            ],
            labels=labels,
            recent_events=[
                dict(
                    audit_id=str(log.id),
                    timestamp=log.timestamp,
                    action=log.action,
                    client_id=log.actor_id,
                    event_id=log.resource_id,
                    risk_score=log.risk_score,
                    risk_factors=log.risk_factors,
                    label=log.label,
                )
                for log in audit_logs.order_by("-timestamp")[:cls.MAX_RECENT_EVENTS]
            ],
        )
