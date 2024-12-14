from uuid import uuid4
from devkit import execute
from django.db import models

from .base import policy_defaults
from .application import Application


def get_kyc_level_limits_default():
    return policy_defaults.kyc_level_limits


class Policy(models.Model):
    defaults = policy_defaults

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    aml_cft_limit = models.CharField(default=defaults.aml_cft_limit)
    kyc_level_limits = models.JSONField(default=get_kyc_level_limits_default)
    device_validity_days = models.IntegerField(default=defaults.device_validity_days)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    application = models.OneToOneField(Application, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Policy"
        verbose_name_plural = "Policies"

    def __str__(self):
        application = execute(lambda: self.application)[0]
        return f"Poilcy ({application.name if application else None})"
