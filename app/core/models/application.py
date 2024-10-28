from uuid import uuid4
from bootkit import execute
from django.db import models
from core.applications.base import generate_encrypted_secret_key

from .organization import Organization


class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=80)
    secret_key = models.CharField(max_length=512, default=generate_encrypted_secret_key)
    device_sdk_key = models.CharField(max_length=512, default=None, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        organization = execute(lambda: self.organization)[0]
        return f"{self.name} ({organization.name if organization else None})"
