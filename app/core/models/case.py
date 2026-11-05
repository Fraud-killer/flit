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


class CasePriority:
    NORMAL = "normal"
    HIGH = "high"

    CHOICES = [
        (NORMAL, "Normal"),
        (HIGH, "High"),
    ]

    VALUES = [value for value, _ in CHOICES]
    ORDER = {HIGH: 0, NORMAL: 1}


class Case(models.Model):
    """
    A decision a human needs to look at. Opened automatically when a decision
    comes back for review, and closing one labels the decision, which is where
    most training data comes from in practice.

    One case per campaign, not per decision. An attacker working two hundred
    accounts from one address used to open two hundred cases, and the queue
    was the attacker's economics: cheaper to generate than to review. Now the
    decisions from one origin in a day land on one case, which counts them.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    status = models.CharField(max_length=20, choices=CaseStatus.CHOICES, default=CaseStatus.OPEN, db_index=True)
    priority = models.CharField(max_length=10, choices=CasePriority.CHOICES, default=CasePriority.NORMAL, db_index=True)
    resolution_note = models.TextField(blank=True)
    opened_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    # The origin the decisions share — `device:<fingerprint>`, `ip:<address>`
    # or `account:<client_id>` — and how many have landed here. Null when the
    # decision had no origin to group on.
    campaign_key = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    decision_count = models.IntegerField(default=1)
    last_decision_at = models.DateTimeField(null=True, blank=True)

    # What the model proposed, when, and whether it was allowed to act.
    # Stored beside the human's verdict so the two can be measured against
    # each other; see core.triage.
    triage_proposal = models.JSONField(null=True, blank=True)
    triage_at = models.DateTimeField(null=True, blank=True)
    triage_auto_closed = models.BooleanField(default=False)

    audit_log = models.OneToOneField(AuditLog, on_delete=models.CASCADE, related_name="case")
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    assignee = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-opened_at"]
        indexes = [
            models.Index(fields=["application", "status", "opened_at"]),
            models.Index(fields=["application", "status", "campaign_key"]),
        ]

    def __str__(self): return f"Case ({self.status})"

    # How long decisions keep landing on the same open case.
    CAMPAIGN_WINDOW_HOURS = 24

    # An ORDER BY that puts high priority first.
    PRIORITY_ORDER = models.Case(
        models.When(priority=CasePriority.HIGH, then=models.Value(0)),
        default=models.Value(1),
        output_field=models.IntegerField(),
    )

    @classmethod
    def campaign_key_for(cls, *, device_fingerprint=None, ip_address=None, client_id=None):
        if device_fingerprint:
            return f"device:{device_fingerprint}"
        if ip_address:
            return f"ip:{ip_address}"
        if client_id:
            return f"account:{client_id}"
        return None

    def decisions(self):
        """Every decision that landed on this case, the first one included."""
        from datetime import timedelta

        if not self.campaign_key:
            return AuditLog.objects.filter(id=self.audit_log_id)

        key, _, value = self.campaign_key.partition(":")
        field = {"device": "device_fingerprint", "ip": "ip_address", "account": "actor_id"}[key]
        until = self.closed_at or (self.last_decision_at or self.opened_at) + timedelta(seconds=1)

        return AuditLog.objects.filter(
            application_id=self.application_id,
            timestamp__gte=self.audit_log.timestamp,
            timestamp__lte=until,
            context__should_review=True,
            **{field: value},
        )

    @property
    def is_open(self):
        return self.status == CaseStatus.OPEN

    def resolve(self, *, status, note="", assignee=None):
        """Close the case and label the decision behind it."""
        # A human overruling an auto-clear is what trips the triage breaker.
        if self.triage_auto_closed and assignee is not None and status != self.status:
            from core.triage import TriageGuardrails
            TriageGuardrails.record_override(self.application, overruled=status == CaseStatus.CONFIRMED_FRAUD)

        self.status = status
        self.resolution_note = note or self.resolution_note
        self.assignee = assignee or self.assignee
        self.closed_at = None if status == CaseStatus.OPEN else timezone.now()
        self.save(update_fields=["status", "resolution_note", "assignee", "closed_at"])

        label = CaseStatus.LABELS.get(status)

        if label:
            from core.services.publish_outcome import PublishOutcome

            audit_log = self.audit_log
            audit_log.label = label
            audit_log.labeled_at = timezone.now()
            audit_log.save(update_fields=["label", "labeled_at"])

            # A closed case is the best ground truth FLIT gets. Publishing it
            # is what turns one merchant's review into the next merchant's
            # defence.
            PublishOutcome.call(audit_log=audit_log, application=self.application)

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
