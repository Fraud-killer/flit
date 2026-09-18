from uuid import uuid4
from secrets import token_urlsafe
from django.db import models

from .application import Application


class DeviceIdentitySource:
    FINGERPRINT = "fingerprint"
    FLIT = "flit"

    CHOICES = [
        (FINGERPRINT, "Fingerprint"),
        (FLIT, "FLIT SDK"),
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

    @staticmethod
    def generate_external_id():
        """The device key FLIT issues to a browser it has not seen before."""
        return f"flit_dk_{token_urlsafe(24)}"

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


class DeviceSignature(models.Model):
    """
    A hashed snapshot of the signals one device produced, used to recognise
    the device on later visits. Only hashes are stored, never raw signals.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    signature_hash = models.CharField(max_length=64, db_index=True)
    components = models.JSONField(default=dict)
    platform = models.CharField(max_length=40, blank=True)
    event_count = models.PositiveIntegerField(default=0)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    device = models.ForeignKey(DeviceIdentity, on_delete=models.CASCADE, related_name="signatures")
    application = models.ForeignKey(Application, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["application", "signature_hash"],
                name="unique_device_signature_per_application",
            ),
        ]
        indexes = [
            models.Index(fields=["application", "platform", "last_seen_at"]),
        ]

    def __str__(self): return f"DeviceSignature ({self.signature_hash[:12]})"
