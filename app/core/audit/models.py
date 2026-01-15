import hashlib
from uuid import uuid4
from django.db import models
from django.utils import timezone


class AuditLogLevel:
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    CHOICES = [
        (DEBUG, "Debug"),
        (INFO, "Info"),
        (WARNING, "Warning"),
        (ERROR, "Error"),
        (CRITICAL, "Critical"),
    ]


class AuditLogCategory:
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    TRANSACTION = "transaction"
    DEVICE = "device"
    POLICY = "policy"
    SECURITY = "security"
    SYSTEM = "system"

    CHOICES = [
        (AUTHENTICATION, "Authentication"),
        (AUTHORIZATION, "Authorization"),
        (TRANSACTION, "Transaction"),
        (DEVICE, "Device"),
        (POLICY, "Policy"),
        (SECURITY, "Security"),
        (SYSTEM, "System"),
    ]


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)

    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    level = models.CharField(max_length=20, choices=AuditLogLevel.CHOICES, db_index=True)
    category = models.CharField(max_length=50, choices=AuditLogCategory.CHOICES, db_index=True)

    action = models.CharField(max_length=100, db_index=True)
    actor_type = models.CharField(max_length=50, null=True, blank=True)
    actor_id = models.CharField(max_length=100, null=True, blank=True, db_index=True)

    resource_type = models.CharField(max_length=50, null=True, blank=True)
    resource_id = models.CharField(max_length=100, null=True, blank=True, db_index=True)

    application_id = models.UUIDField(null=True, blank=True, db_index=True)
    organization_id = models.UUIDField(null=True, blank=True, db_index=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    device_fingerprint = models.CharField(max_length=100, null=True, blank=True)

    request_id = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    request_method = models.CharField(max_length=10, null=True, blank=True)
    request_path = models.CharField(max_length=500, null=True, blank=True)

    context = models.JSONField(default=dict)
    risk_score = models.FloatField(null=True, blank=True)
    risk_factors = models.JSONField(default=list)

    outcome = models.CharField(max_length=50, null=True, blank=True)
    error_code = models.CharField(max_length=50, null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)

    previous_hash = models.CharField(max_length=64, null=True, blank=True)
    entry_hash = models.CharField(max_length=64, editable=False)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["application_id", "timestamp"]),
            models.Index(fields=["actor_id", "timestamp"]),
            models.Index(fields=["category", "action", "timestamp"]),
            models.Index(fields=["risk_score"]),
        ]

    def save(self, *args, **kwargs):
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()
        super().save(*args, **kwargs)

    def _compute_hash(self) -> str:
        content = (
            f"{self.timestamp.isoformat()}:"
            f"{self.level}:"
            f"{self.category}:"
            f"{self.action}:"
            f"{self.actor_type}:{self.actor_id}:"
            f"{self.resource_type}:{self.resource_id}:"
            f"{self.application_id}:"
            f"{self.ip_address}:"
            f"{self.request_id}:"
            f"{self.outcome}:"
            f"{self.previous_hash or 'genesis'}"
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        return self.entry_hash == self._compute_hash()

    def __str__(self):
        return f"[{self.timestamp}] {self.level.upper()}: {self.category}/{self.action}"


class AuditLogArchive(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    archive_date = models.DateField(db_index=True)
    start_timestamp = models.DateTimeField()
    end_timestamp = models.DateTimeField()
    record_count = models.IntegerField()
    file_path = models.CharField(max_length=500)
    file_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-archive_date"]
