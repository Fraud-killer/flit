"""
The switches and breakers around the agent.

- A kill switch: AGENT_ENABLED in the environment, and `enabled` on the
  organization's and the application's agent policy. Any one off is off.
- A daily budget per application, kept in the cache like the triage counters:
  hot, short-lived, recomputable from the Investigation rows if lost.
- A denial streak: three writes the classifier refuses in one run drop the
  run from auto to ask for its remainder.
- A circuit breaker: three consecutive human rejections of actions the agent
  took on its own trip the application to ask mode until a person resets it.
"""

from django.core.cache import cache
from django.utils import timezone

from kernel.config import Config


class AgentGuardrails:
    MAX_CLASSIFIER_DENIALS = 3
    MAX_CONSECUTIVE_REJECTIONS = 3

    @classmethod
    def enabled_globally(cls):
        return bool(getattr(Config, "agent_enabled", False))

    @classmethod
    def disabled_reason(cls, application, application_policy, organization_policy=None):
        if not cls.enabled_globally():
            return "AGENT_ENABLED is off"
        if organization_policy is not None and not organization_policy.enabled:
            return "the organization has switched the agent off"
        if not application_policy.enabled:
            return "the agent is switched off for this application"
        return None

    # -- daily budget -------------------------------------------------------------

    @classmethod
    def budget_key(cls, application_id):
        return f"flit:agent:{application_id}:spend:{timezone.now():%Y%m%d}"

    @classmethod
    def spent_today(cls, application_id):
        try:
            return float(cache.get(cls.budget_key(application_id)) or 0.0)
        except Exception:
            return 0.0

    @classmethod
    def record_spend(cls, application_id, cost_usd):
        key = cls.budget_key(application_id)
        try:
            total = float(cache.get(key) or 0.0) + float(cost_usd)
            cache.set(key, total, 2 * 24 * 60 * 60)
            return total
        except Exception:
            return 0.0

    @classmethod
    def within_daily_budget(cls, application_id, daily_budget_usd):
        return cls.spent_today(application_id) < float(daily_budget_usd)

    # -- the breaker --------------------------------------------------------------

    @classmethod
    def breaker_keys(cls, application_id):
        base = f"flit:agent:{application_id}"
        return f"{base}:tripped", f"{base}:rejections"

    @classmethod
    def record_review(cls, application, *, rejected):
        """A person reviewed an action the agent took unattended."""
        tripped_key, rejections_key = cls.breaker_keys(application.id)
        if not rejected:
            cache.delete(rejections_key)
            return 0
        count = int(cache.get(rejections_key) or 0) + 1
        cache.set(rejections_key, count, 30 * 24 * 60 * 60)
        if count >= cls.MAX_CONSECUTIVE_REJECTIONS:
            cache.set(tripped_key, timezone.now().isoformat(), None)
        return count

    @classmethod
    def tripped(cls, application):
        tripped_key, _ = cls.breaker_keys(application.id)
        try:
            return cache.get(tripped_key)
        except Exception:
            return None

    @classmethod
    def reset(cls, application):
        cache.delete_many(list(cls.breaker_keys(application.id)))
