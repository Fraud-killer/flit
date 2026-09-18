from django.db.models import F
from django.utils import timezone
from core.models import DeviceIdentity, DeviceAccountLink
from core.models.device_identity import DeviceIdentitySource


class ResolveDeviceIdentity:
    """
    Find or create the DeviceIdentity for a Fingerprint visit, refresh its
    latest signals, and link it to the account that used it.
    """

    @classmethod
    def call(cls, *, visit, application, client_id=None):
        if visit is None or not getattr(visit, "fingerprint", None):
            return None

        now = timezone.now()
        signals = getattr(visit, "device_signals", None) or {}

        identity, _ = DeviceIdentity.objects.get_or_create(
            source=getattr(visit, "source", DeviceIdentitySource.FINGERPRINT),
            external_id=visit.fingerprint,
        )

        DeviceIdentity.objects.filter(pk=identity.pk).update(
            flags=sorted(flag for flag, value in signals.items() if value),
            last_ip_address=getattr(visit, "ip", None),
            last_country=getattr(visit, "country", None) or getattr(visit, "country_code", None),
            event_count=F("event_count") + 1,
            last_seen_at=now,
        )

        if client_id:
            link, _ = DeviceAccountLink.objects.get_or_create(
                device=identity,
                application=application,
                client_id=client_id,
            )

            DeviceAccountLink.objects.filter(pk=link.pk).update(
                event_count=F("event_count") + 1,
                last_seen_at=now,
            )

        identity.refresh_from_db()
        return identity
