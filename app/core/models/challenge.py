from uuid import uuid4
from hashlib import sha256
from secrets import compare_digest, randbelow
from django.db import models
from django.utils import timezone

from core.audit.models import AuditLog

from .application import Application


class ChallengeMethod:
    TURNSTILE = "turnstile"
    OTP = "otp"

    CHOICES = [
        (TURNSTILE, "Cloudflare Turnstile"),
        (OTP, "One-time code"),
    ]

    VALUES = [value for value, _ in CHOICES]


class ChallengeStatus:
    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    EXPIRED = "expired"

    CHOICES = [
        (PENDING, "Pending"),
        (PASSED, "Passed"),
        (FAILED, "Failed"),
        (EXPIRED, "Expired"),
    ]

    VALUES = [value for value, _ in CHOICES]


class Challenge(models.Model):
    """
    A step-up FLIT has asked an actor to clear.

    The point of a challenge is not certainty, it is price. At the signup
    surface the evidence is thin by nature, and blocking on thin evidence
    costs real customers; a challenge leaves the honest user with one puzzle
    and leaves the automated one with a cost per account it did not have.

    The outcome is evidence in its own right: a failed or abandoned challenge
    is recorded against the identity keys behind it, so the next decision
    knows.
    """

    DEFAULT_TTL_SECONDS = 15 * 60
    DEFAULT_MAX_ATTEMPTS = 5

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    client_id = models.CharField(max_length=80, db_index=True)
    method = models.CharField(max_length=20, choices=ChallengeMethod.CHOICES)
    status = models.CharField(
        max_length=20, choices=ChallengeStatus.CHOICES,
        default=ChallengeStatus.PENDING, db_index=True,
    )

    # For OTP only, and only ever the digest. The code itself is returned to
    # the merchant once, at issue, and never stored.
    secret_hash = models.CharField(max_length=64, blank=True)

    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=DEFAULT_MAX_ATTEMPTS)

    # The identity keys resolved for the decision that asked for this
    # challenge, so its outcome can be attributed without re-resolving them.
    identity_key_ids = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    audit_log = models.ForeignKey(
        AuditLog, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="challenges",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["application", "client_id", "created_at"]),
            models.Index(fields=["application", "status", "created_at"]),
        ]

    def __str__(self):
        return f"Challenge ({self.method}:{self.status})"

    @staticmethod
    def generate_code():
        """A six-digit code, from the same CSPRNG as everything else here."""
        return f"{randbelow(1_000_000):06d}"

    @staticmethod
    def hash_code(code):
        return sha256(str(code).encode("utf-8")).hexdigest()

    def matches(self, code):
        """Constant-time comparison, so a wrong code leaks nothing by timing."""
        if not self.secret_hash or code is None:
            return False

        return compare_digest(self.secret_hash, self.hash_code(code))

    @property
    def is_expired(self):
        return timezone.now() >= self.expires_at

    @property
    def is_open(self):
        return self.status == ChallengeStatus.PENDING and not self.is_expired

    @property
    def attempts_remaining(self):
        return max(self.max_attempts - self.attempts, 0)
