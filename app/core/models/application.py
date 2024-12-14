from uuid import uuid4
from devkit import execute
from django.db import models
from kernel.mcrypt import decrypt

from .organization import Organization


class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    name = models.CharField(max_length=80)
    secret_key = models.CharField(max_length=512, null=True, blank=True)
    device_sdk_key = models.CharField(max_length=512, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    @property
    def raw_secret_key(self):
        return decrypt(self.secret_key)

    @property
    def raw_device_sdk_key(self):
        return decrypt(self.device_sdk_key)
