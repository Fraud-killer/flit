from uuid import uuid4
from secrets import token_urlsafe
from core import mcrypt
from django.db import models

from .organization import Organization


def generate_collect_key():
    """Public key embedded in the browser SDK. Identifies, never authorises."""
    return f"flit_pk_{token_urlsafe(24)}"


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
    def reads_network(self):
        """
        Whether this application may read the network.

        Reciprocal by design: a merchant who publishes nothing gets nothing
        back. A one-way reader would learn about other merchants' fraud while
        contributing none of their own, and a network nobody feeds is worth
        nothing to belong to.
        """
        return self.consumes_network and self.contributes_to_network
