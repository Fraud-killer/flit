"""
What FLIT remembers about money leaving through a credential.

A per-account score cannot see one credential draining many accounts: each
transfer is ordinary for the account it left. These two records hold the view
across accounts. See core.services.outflow_window and the two rules that read
them.
"""

from uuid import uuid4

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from .application import Application


class InitiatorBeneficiary(models.Model):
    """
    A credential has paid this beneficiary from this account.

    Being seen is not being trusted. A link is trusted once it has aged
    through the cooling period without a fraud label, or when a person
    approved it. Otherwise an attacker's own transfers would teach FLIT that
    their beneficiaries are normal.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    initiator_id = models.CharField(max_length=128)
    client_id = models.CharField(max_length=128)
    beneficiary_key = models.CharField(max_length=255)

    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(default=timezone.now)
    transfer_count = models.IntegerField(default=0)

    approved_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+",
    )
    # A fraud label on any transfer over this link. Wins over age and approval.
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["application", "initiator_id", "client_id", "beneficiary_key"],
                name="unique_initiator_beneficiary",
            ),
        ]

    def trusted(self, *, cooling, now):
        if self.revoked_at is not None:
            return False
        return self.approved_at is not None or self.first_seen_at <= now - cooling


class OutflowTrip(models.Model):
    """
    A scope that went over its limit and stays stopped.

    Windows slide, so without this a stopped credential would reopen by
    itself in the middle of the night. Only a signed-in person releases one.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    application = models.ForeignKey(Application, on_delete=models.CASCADE)
    scope_kind = models.CharField(max_length=20)
    scope_value = models.CharField(max_length=128)

    window = models.CharField(max_length=8)
    limit_minor = models.BigIntegerField()
    used_minor = models.BigIntegerField()
    currency_code = models.CharField(max_length=3)
    trigger_audit_id = models.UUIDField(null=True, blank=True)

    tripped_at = models.DateTimeField(default=timezone.now)
    released_at = models.DateTimeField(null=True, blank=True)
    released_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+",
    )
    release_note = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["-tripped_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["application", "scope_kind", "scope_value"],
                condition=Q(released_at__isnull=True),
                name="one_open_outflow_trip_per_scope",
            ),
        ]
