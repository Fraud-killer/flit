from uuid import uuid4
from secrets import token_urlsafe
from core import mcrypt
from django.db import models

from .organization import Organization


def generate_collect_key():
    """Public key embedded in the browser SDK. Identifies, never authorises."""
    return f"flit_pk_{token_urlsafe(24)}"


class Enforcement:
    """
    Whether FLIT's decisions actually do anything yet.

    A fraud tool that starts blocking on its first day is a fraud tool that
    turns away real customers on its first day, on thresholds nobody has
    measured against this merchant's traffic. Shadow is how that is avoided:
    every decision is computed and recorded exactly as it would be in
    production, and none of it is acted on. After a few weeks the merchant
    has their own numbers — false positive rate, what would have been
    blocked, which rules fired on customers they know are good — and can turn
    enforcement on with evidence instead of hope.

    It is also the rung the evidence ladder is named for: a detector that has
    run against live traffic without acting on it is `shadow_validated`.
    """

    SHADOW = "shadow"
    ENFORCING = "enforcing"

    CHOICES = [
        (SHADOW, "Shadow — decide and record, act on nothing"),
        (ENFORCING, "Enforcing — decisions are acted on"),
    ]

    VALUES = [value for value, _ in CHOICES]


class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=80)
    secret_key = models.CharField(max_length=512, null=True, blank=True)
    visit_sdk_key = models.CharField(max_length=512, null=True, blank=True)
    collect_key = models.CharField(max_length=64, unique=True, default=generate_collect_key)
    # Origins allowed to use collect_key. Empty accepts any origin.
    collect_origins = models.JSONField(default=list, blank=True)

    # Cloudflare Turnstile secret for this application's step-up challenges.
    # Falls back to the deployment-wide secret when unset.
    turnstile_secret = models.CharField(max_length=512, null=True, blank=True)

    # Participation in the shared protection network. Contributing publishes
    # this application's confirmed outcomes as observations; consuming reads
    # what other applications confirmed. See core.services.network_reputation
    # for exactly what crosses the boundary — never raw data, and never which
    # merchant saw what.
    contributes_to_network = models.BooleanField(default=True)
    consumes_network = models.BooleanField(default=True)

    # New applications start in shadow. Enforcing is a decision a merchant
    # makes once they have seen what FLIT would have done to their own
    # traffic, never a default they inherit without noticing.
    enforcement = models.CharField(
        max_length=20, choices=Enforcement.CHOICES, default=Enforcement.SHADOW,
    )

    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    @property
    def raw_secret_key(self):
        return mcrypt.decrypt(self.secret_key)

    @property
    def raw_visit_sdk_key(self):
        return mcrypt.decrypt(self.visit_sdk_key)

    @property
    def raw_turnstile_secret(self):
        from kernel.config import Config

        if self.turnstile_secret:
            return mcrypt.decrypt(self.turnstile_secret)

        return Config.turnstile_secret_key

    @property
    def is_enforcing(self):
        return self.enforcement == Enforcement.ENFORCING

    @property
    def reads_network(self):
        """
        Whether this application may read the network.

        Reciprocal by design: a merchant who publishes nothing gets nothing
        back. A one-way reader would learn about other merchants' fraud while
        contributing none of their own, and a network nobody feeds is worth
        nothing to belong to.
        """
        return self.consumes_network and self.contributes_to_network
