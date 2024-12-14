from uuid import uuid4
from django.db import models
from core.models.application import Application


class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    client_id = models.CharField(max_length=80)
    fingerprint = models.CharField(max_length=80)
    locations = models.JSONField(default=list)
    raw_data = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    application = models.ForeignKey(Application, on_delete=models.CASCADE)

    def __str__(self): return f"Device ({self.fingerprint})"
