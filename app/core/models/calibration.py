from uuid import uuid4
from django.db import models

from .application import Application


class CalibrationMode:
    # Computed and recorded; nothing changed. The default.
    DRY_RUN = "dry_run"
    # Proposals passed the guardrails and were written to the policy.
    APPLIED = "applied"
    # Nothing was changed because the evidence did not justify it: too few
    # labels, or the proposals together failed a guardrail. The reason says
    # which, and that is what a reviewer reads.
    HELD = "held"

    CHOICES = [
        (DRY_RUN, "Dry run — computed, not applied"),
        (APPLIED, "Applied — the policy was changed"),
        (HELD, "Held — the evidence did not justify a change"),
    ]

    VALUES = [value for value, _ in CHOICES]


class CalibrationRun(models.Model):
    """
    One pass of the calibrator over an application's labelled history.

    This is the ledger a human reviews. The loop that reads outcomes and moves
    weights runs on its own; what it must never do is move them silently. Every
    run records the sample it saw, what it proposed, what it accepted and why,
    the measured effect before and after, and whether it was applied. A
    reviewer's job is the calibration, not the cases.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="calibration_runs")
    started_at = models.DateTimeField(auto_now_add=True, db_index=True)
    window_days = models.IntegerField()

    # The sample. Labels come from reviewers closing cases and merchants
    # reporting outcomes; without enough of them a run is held.
    decisions = models.IntegerField(default=0)
    labelled = models.IntegerField(default=0)
    fraud = models.IntegerField(default=0)
    legit = models.IntegerField(default=0)

    mode = models.CharField(max_length=20, choices=CalibrationMode.CHOICES, default=CalibrationMode.DRY_RUN)
    reason = models.TextField(blank=True, default="")

    # Each proposal: code, from, to, direction, the per-code measurement that
    # motivated it, whether it was accepted, and the guardrail that rejected
    # it if not.
    proposals = models.JSONField(default=list, blank=True)
    # Blocked, caught, missed, false positives, precision, recall and
    # false-positive rate under the weights in force and under the accepted
    # proposals, measured on the same labelled rows.
    before = models.JSONField(default=dict, blank=True)
    after = models.JSONField(default=dict, blank=True)
    # What each candidate block threshold would have done, for the reviewer.
    threshold_sweep = models.JSONField(default=list, blank=True)
    # Per-code measurements with enough labels behind them to mean something.
    measured = models.JSONField(default=list, blank=True)

    applied = models.BooleanField(default=False)
    applied_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["application", "started_at"])]

    def __str__(self):
        return f"CalibrationRun ({self.mode}, {self.started_at:%Y-%m-%d})"

    @property
    def accepted(self):
        return [proposal for proposal in self.proposals if proposal.get("accepted")]
