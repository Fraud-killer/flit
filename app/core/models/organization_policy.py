from uuid import uuid4
from django.db import models

from .organization import Organization


class OrganizationPolicy(models.Model):
    """
    What every application under an organization inherits, and the ceiling
    none of them may exceed.

    A bank runs many applications. Its fraud team needs to say once that a
    sanctioned range is blocked everywhere, that no application may block
    later than 0.8, that shadow mode is not an option for the card product —
    and to know that no application's own policy can undo any of it. An
    application may always be stricter than its organization. It may never be
    looser.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    organization = models.OneToOneField(Organization, on_delete=models.CASCADE, related_name="policy")

    # Decision rules applied to every application, before its own. See
    # core.decision.rules for the shape. An application cannot remove them.
    rules = models.JSONField(default=dict, blank=True)

    # Ceilings on the thresholds an application may decide with. An
    # application's block_at is min(its own, this); likewise review_at.
    max_block_at = models.FloatField(null=True, blank=True)
    max_review_at = models.FloatField(null=True, blank=True)

    # "enforcing" makes every application under the organization enforce,
    # whatever its own setting says. Null leaves it to each application.
    required_enforcement = models.CharField(max_length=20, null=True, blank=True)

    # Rule class names switched off for every application. The central kill
    # switch for a rule that is misfiring across the estate.
    disabled_rules = models.JSONField(default=list, blank=True)

    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Organization policy"
        verbose_name_plural = "Organization policies"

    def __str__(self):
        return f"OrganizationPolicy ({self.organization_id})"

    @classmethod
    def for_application(cls, application):
        """The organization's policy, or None when it has not set one."""
        organization_id = getattr(application, "organization_id", None)
        if not organization_id:
            return None
        return cls.objects.filter(organization_id=organization_id).first()

    @property
    def requires_enforcing(self):
        from .application import Enforcement
        return self.required_enforcement == Enforcement.ENFORCING
