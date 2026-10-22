from uuid import uuid4
from hashlib import sha256
from django.db import models

from core.identity_keys import IdentityKeyType as IdentityKeyType

from .application import Application


class IdentityKey(models.Model):
    """
    One correlation key across all of FLIT, stored as a hash.

    Keys are global — the same IP seen attacking one merchant is the same row
    another merchant's audit resolves — but nothing about who else has seen it
    is exposed to a merchant except through their own IdentityAccountLink rows.
    That split is what lets FLIT learn across the network without leaking one
    merchant's traffic to another.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    key_type = models.CharField(max_length=20, choices=IdentityKeyType.CHOICES)
    value_hash = models.CharField(max_length=64)
    # A human-readable, non-reversing form for analysts. Never the raw email.
    preview = models.CharField(max_length=120, blank=True)
    event_count = models.PositiveIntegerField(default=0)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["key_type", "value_hash"],
                name="unique_identity_key",
            ),
        ]
        indexes = [
            models.Index(fields=["key_type", "last_seen_at"]),
        ]

    @staticmethod
    def hash_value(key_type, value):
        """
        Namespaced so the same string under two key types cannot collide, and
        so a raw value is never recoverable from the stored digest.
        """
        return sha256(f"{key_type}:{value}".encode("utf-8")).hexdigest()

    def __str__(self):
        return f"IdentityKey ({self.key_type}:{self.value_hash[:12]})"


class IdentityAccountLink(models.Model):
    """
    An account of an application seen under one identity key.

    The generalisation of DeviceAccountLink: same shape, same access pattern,
    but the key can be any rung of the ladder rather than a device alone.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    client_id = models.CharField(max_length=80)
    event_count = models.PositiveIntegerField(default=0)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    identity_key = models.ForeignKey(
        IdentityKey, on_delete=models.CASCADE, related_name="account_links",
    )
    application = models.ForeignKey(Application, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["identity_key", "application", "client_id"],
                name="unique_identity_account_link",
            ),
        ]
        indexes = [
            # AccountFarmingRule: accounts first seen on a key within a day.
            models.Index(fields=["identity_key", "application", "first_seen_at"]),
            # MultiAccountingRule: accounts still active on a key.
            models.Index(fields=["identity_key", "application", "last_seen_at"]),
        ]

    def __str__(self):
        return f"IdentityAccountLink ({self.client_id} on {self.identity_key_id})"


class IdentityObservation(models.Model):
    """
    What one application has learned about one identity key.

    This is the unit of the shared protection network. Each row is a single
    merchant's own experience — cases they confirmed as fraud, challenges the
    actor failed — and the network is the sum of those rows across merchants.

    It is stored per application rather than as a global counter for one
    reason: when a merchant asks the network about a key, their own rows are
    excluded from the answer. What they get back is strictly what *others*
    have seen, which is the only part that is new information, and it keeps a
    merchant from reading their own data back as though it were corroboration.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)

    fraud_count = models.PositiveIntegerField(default=0)
    legit_count = models.PositiveIntegerField(default=0)
    challenge_failed_count = models.PositiveIntegerField(default=0)
    challenge_passed_count = models.PositiveIntegerField(default=0)

    last_fraud_at = models.DateTimeField(null=True, blank=True)
    last_legit_at = models.DateTimeField(null=True, blank=True)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    identity_key = models.ForeignKey(
        IdentityKey, on_delete=models.CASCADE, related_name="observations",
    )
    application = models.ForeignKey(Application, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["identity_key", "application"],
                name="unique_identity_observation",
            ),
        ]
        indexes = [
            # The network query: everything known about a key, most recent
            # confirmations first, filtered to exclude the asking merchant.
            models.Index(fields=["identity_key", "last_fraud_at"]),
        ]

    def __str__(self):
        return f"IdentityObservation ({self.identity_key_id} @ {self.application_id})"
