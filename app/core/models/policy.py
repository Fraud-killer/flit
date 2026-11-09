from uuid import uuid4
from devkit import execute
from django.db import models

from .base import policy_defaults
from .application import Application


def get_kyc_level_limits_default():
    return policy_defaults.kyc_level_limits


def get_device_thresholds_default():
    return dict()


class Policy(models.Model):
    defaults = policy_defaults

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    aml_cft_limit = models.CharField(default=defaults.aml_cft_limit)
    kyc_level_limits = models.JSONField(default=get_kyc_level_limits_default)
    device_validity_days = models.IntegerField(default=defaults.device_validity_days)
    # Overrides for core.audit.rules.device_thresholds.DEFAULT_DEVICE_THRESHOLDS
    device_thresholds = models.JSONField(default=get_device_thresholds_default, blank=True)
    # Overrides for core.audit.rules.mule_thresholds.DEFAULT_MULE_THRESHOLDS
    mule_thresholds = models.JSONField(default=get_device_thresholds_default, blank=True)
    # Overrides for core.audit.rules.identity_thresholds.DEFAULT_IDENTITY_THRESHOLDS,
    # merged one level deep so a single ladder key can be retuned on its own.
    identity_thresholds = models.JSONField(default=get_device_thresholds_default, blank=True)
    # Overrides for core.audit.rules.crypto_thresholds.DEFAULT_CRYPTO_THRESHOLDS
    crypto_thresholds = models.JSONField(default=get_device_thresholds_default, blank=True)
    # Value ceilings per credential, channel and application. Empty applies
    # none. See core.services.outflow_window for the shape.
    outflow_limits = models.JSONField(default=get_device_thresholds_default, blank=True)
    # {"enabled", "cooling_hours", "fail"}: refuse a credential paying a
    # beneficiary it has no trusted history with. See core.services.money_out.
    beneficiary_control = models.JSONField(default=get_device_thresholds_default, blank=True)
    # What the calibrator has learned from this application's outcomes:
    # `weights` (per-code overrides on core.scoring.DEFAULT_WEIGHTS),
    # `thresholds` (block_at / review_at), `calibrated_at` and the `run_id`
    # that wrote them. Read at decision time by core.calibration.engine_for.
    # Written only by a CalibrationRun that passed its guardrails, so every
    # value here can be traced to the run and the labelled rows behind it.
    calibration = models.JSONField(default=dict, blank=True)
    # How long the rules may take, together, before the decision is made
    # with what has arrived. A rule still running at the deadline is
    # reported as unavailable; see core.audit.auditor.Auditor._run_rules.
    latency_budget_ms = models.IntegerField(default=defaults.latency_budget_ms)
    # Decisions a person has made in plain terms, applied before the score:
    # {"block": [...], "review": [...], "challenge": [...], "allow": [...]},
    # each entry {subject, pattern, reason?, expires_at?}. See core.decision.
    rules = models.JSONField(default=dict, blank=True)
    # Rule class names this application has switched off. The kill switch
    # for a rule that is misfiring on this merchant's traffic, usable without
    # a deploy. A disabled rule is recorded on every decision it sat out.
    disabled_rules = models.JSONField(default=list, blank=True)
    # Rule class names that run but do not count. Their findings are recorded
    # under the decision's `shadow` context and measured by
    # `manage.py shadow_report`; this is how a proposed rule earns the
    # shadow-validated rung against live traffic without acting on anyone.
    shadow_rules = models.JSONField(default=list, blank=True)
    # When set ("otp" or "turnstile"), a decision that asks for a step-up
    # issues the challenge itself and returns it, so the merchant verifies and
    # replays with `challenge_id` instead of making a second call. Null leaves
    # issuing to the merchant.
    challenge_method = models.CharField(max_length=20, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    application = models.OneToOneField(Application, on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Policy"
        verbose_name_plural = "Policies"

    def __str__(self):
        application = execute(lambda: self.application)[0]
        return f"Poilcy ({application.name if application else None})"
