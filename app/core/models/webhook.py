from uuid import uuid4
from django.db import models

from .application import Application


class WebhookStatus:
    PENDING = "pending"
    DELIVERED = "delivered"
    DEAD = "dead"

    CHOICES = [
        (PENDING, "Pending"),
        (DELIVERED, "Delivered"),
        (DEAD, "Dead — gave up"),
    ]


class WebhookDelivery(models.Model):
    """
    One event FLIT owes a merchant's endpoint.

    Deliveries are rows, not fire-and-forget requests, because the
    merchant's server will be down at some point and the case that opened
    while it was down still matters. A cron command drains the queue with
    backoff, and a delivery that has failed enough times is parked as dead
    rather than retried forever.
    """

    MAX_ATTEMPTS = 8

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name="webhook_deliveries")
    event = models.CharField(max_length=60, db_index=True)
    payload = models.JSONField(default=dict)

    status = models.CharField(max_length=20, choices=WebhookStatus.CHOICES, default=WebhookStatus.PENDING, db_index=True)
    attempts = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(db_index=True)
    last_status_code = models.IntegerField(null=True, blank=True)
    last_error = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["next_attempt_at"]
        indexes = [models.Index(fields=["status", "next_attempt_at"])]

    def __str__(self):
        return f"WebhookDelivery ({self.event}, {self.status})"
