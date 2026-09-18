from uuid import uuid4
from django.db import models
from django.utils import timezone

from .user import User
from .application import Application
from core.audit.models import AuditLog, AuditLogLabel


class CaseStatus:
    OPEN = "open"
    CONFIRMED_FRAUD = "confirmed_fraud"
    CLEARED = "cleared"

    CHOICES = [
        (OPEN, "Open"),
        (CONFIRMED_FRAUD, "Confirmed fraud"),
        (CLEARED, "Cleared"),
    ]

    VALUES = [value for value, _ in CHOICES]

    # Closing a case is how a reviewer labels the decision behind it.
    LABELS = {
        CONFIRMED_FRAUD: AuditLogLabel.FRAUD,
        CLEARED: AuditLogLabel.LEGIT,
    }


class Case(models.Model):
    """
    A decision a human needs to look at. Opened automatically when a decision
    comes back for review, and closing one labels the decision, which is where
    most training data comes from in practice.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    status = models.CharField(max_length=20, choices=CaseStatus.CHOICES, default=CaseStatus.OPEN, db_index=True)
    resolution_note = models.TextField(blank=True)
    opened_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    audit_log = models.OneToOneField(AuditLog, on_delete=models.CASCADE, related_name="case")
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    assignee = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-opened_at"]
        indexes = [
            models.Index(fields=["application", "status", "opened_at"]),
        ]

    def __str__(self): return f"Case ({self.status})"

    @property
    def is_open(self):
        return self.status == CaseStatus.OPEN

    def resolve(self, *, status, note="", assignee=None):
        """Close the case and label the decision behind it."""
        self.status = status
        self.resolution_note = note or self.resolution_note
        self.assignee = assignee or self.assignee
        self.closed_at = None if status == CaseStatus.OPEN else timezone.now()
        self.save(update_fields=["status", "resolution_note", "assignee", "closed_at"])

        label = CaseStatus.LABELS.get(status)

        if label:
            audit_log = self.audit_log
            audit_log.label = label
            audit_log.labeled_at = timezone.now()
            audit_log.save(update_fields=["label", "labeled_at"])

        return self


class CaseNote(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="notes")
    author = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["created_at"]

    def __str__(self): return f"CaseNote ({self.case_id})"
