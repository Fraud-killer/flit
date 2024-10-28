from uuid import uuid4
from bootkit import execute
from django.db import models
from core.policies import entries

from .application import Application


def get_aml_cft_limit_default():
    return entries.AmlCftLimit.default


def get_kyc_level_limits_default():
    return entries.KycLevelLimits.default


class Policy(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    aml_cft_limit = models.JSONField(default=get_aml_cft_limit_default)
    kyc_level_limits = models.JSONField(default=get_kyc_level_limits_default)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    application = models.OneToOneField(Application, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Policy"
        verbose_name_plural = "Policies"

    def __str__(self):
        application = execute(lambda: self.application)[0]
        return f"Poilcy ({application.name if application else None})"
