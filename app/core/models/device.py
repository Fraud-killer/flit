from uuid import uuid4
from django.db import models
from core.models.application import Application


class Device(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    end_user_id = models.CharField(max_length=80)
    raw_data = models.JSONField(default=dict)
    fingerprint = models.CharField(max_length=80)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    application = models.ForeignKey(Application, on_delete=models.CASCADE)

    def __str__(self): return f"Device ({self.fingerprint})"
