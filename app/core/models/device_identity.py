from uuid import uuid4
from django.db import models

from .application import Application


class DeviceIdentitySource:
    FINGERPRINT = "fingerprint"

    CHOICES = [
        (FINGERPRINT, "Fingerprint"),
    ]


class DeviceIdentity(models.Model):
    """
    One physical device across all of FLIT, keyed by the identifier a source
    (Fingerprint today, FLIT's own SDKs later) assigned to it.

    Identities are global, but everything exposed to a merchant is scoped to
    their application through DeviceAccountLink.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    source = models.CharField(max_length=20, choices=DeviceIdentitySource.CHOICES)
    external_id = models.CharField(max_length=100)
    flags = models.JSONField(default=list)
    last_ip_address = models.GenericIPAddressField(null=True, blank=True)
    last_country = models.CharField(max_length=80, null=True, blank=True)
    event_count = models.PositiveIntegerField(default=0)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source", "external_id"],
                name="unique_device_identity_per_source",
            ),
        ]

    def __str__(self): return f"DeviceIdentity ({self.source}:{self.external_id})"


class DeviceAccountLink(models.Model):
    """An account (client_id) of an application seen on a device."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    client_id = models.CharField(max_length=80)
    event_count = models.PositiveIntegerField(default=0)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    device = models.ForeignKey(DeviceIdentity, on_delete=models.CASCADE, related_name="account_links")
    application = models.ForeignKey(Application, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["device", "application", "client_id"],
                name="unique_device_account_link",
            ),
        ]
        indexes = [
            models.Index(fields=["device", "application", "last_seen_at"]),
            models.Index(fields=["application", "client_id", "last_seen_at"]),
        ]

    def __str__(self): return f"DeviceAccountLink ({self.client_id} on {self.device_id})"
