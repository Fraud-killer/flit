"""
When a proposal may become a decision.

Shadow first: proposals are written beside the human's verdict and measured.
Auto-clearing is a second, separate switch, and it stays off until the
measurement says it has earned it — and goes off again the moment humans
start overruling it.

- Precision on `cleared` over the last human-closed cases must be at or
  above the floor, over at least the minimum sample. The reviewer never sees
  the proposal on an open case, so the measurement is blind. The sample is
  one hundred: with no disagreement in a hundred, the true miss rate is
  under about three percent at 95% confidence; fifty would only have bounded
  it at six.
- A daily cap on auto-clears per application, so a bad hour is a bad hour.
- A circuit breaker: three consecutive auto-cleared cases later shown to be
  fraud — a reviewer reopening the case, or a fraud or chargeback outcome
  reported on the decision through the API — and auto-clearing stops for the
  application until a person re-enables it.
- An auto-clear labels nothing and publishes nothing. The decision stays
  unlabelled until a person closes the case, so the model's guesses never
  train the weights or reach the network.
"""

from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone


class TriageGuardrails:
    MIN_PRECISION = 0.99
    MIN_AGREEMENTS = 100
    DAILY_CAP = 200
    MAX_CONSECUTIVE_OVERRIDES = 3
    WINDOW_DAYS = 60

    @classmethod
    def keys(cls, application_id):
        base = f"flit:triage:{application_id}"
        return f"{base}:tripped", f"{base}:overrides", f"{base}:cleared:{timezone.now():%Y%m%d}"

    @classmethod
    def measure(cls, application):
        """
        How the proposals have agreed with humans so far, on cases a human
        closed after a proposal was written.
        """
        from core.models import Case, CaseStatus

        since = timezone.now() - timedelta(days=cls.WINDOW_DAYS)
        closed = (
            Case.objects
            .filter(application=application, closed_at__gte=since, triage_proposal__isnull=False)
            .exclude(status=CaseStatus.OPEN)
            .exclude(triage_auto_closed=True)
        )

        proposed_cleared = agreed_cleared = 0
        proposed_fraud = agreed_fraud = 0
        deferred = 0

        for case in closed:
            verdict = (case.triage_proposal or {}).get("verdict")
            if verdict == "cleared":
                proposed_cleared += 1
                agreed_cleared += case.status == CaseStatus.CLEARED
            elif verdict == "confirmed_fraud":
                proposed_fraud += 1
                agreed_fraud += case.status == CaseStatus.CONFIRMED_FRAUD
            else:
                deferred += 1

        return dict(
            closed=closed.count(),
            proposed_cleared=proposed_cleared,
            agreed_cleared=agreed_cleared,
            cleared_precision=round(agreed_cleared / proposed_cleared, 4) if proposed_cleared else None,
            proposed_fraud=proposed_fraud,
            agreed_fraud=agreed_fraud,
            fraud_precision=round(agreed_fraud / proposed_fraud, 4) if proposed_fraud else None,
            deferred=deferred,
        )

    @classmethod
    def may_auto_clear(cls, application):
        """(allowed, reason)."""
        tripped_key, _, cleared_key = cls.keys(application.id)

        if cache.get(tripped_key):
            return False, "circuit breaker tripped: humans overruled consecutive auto-clears"

        if int(cache.get(cleared_key) or 0) >= cls.DAILY_CAP:
            return False, f"daily cap of {cls.DAILY_CAP} auto-clears reached"

        measured = cls.measure(application)
        if measured["proposed_cleared"] < cls.MIN_AGREEMENTS:
            return False, (
                f"not enough measurement: {measured['proposed_cleared']} cleared proposals "
                f"closed by a human, needs {cls.MIN_AGREEMENTS}"
            )
        if (measured["cleared_precision"] or 0) < cls.MIN_PRECISION:
            return False, f"cleared precision {measured['cleared_precision']} is under {cls.MIN_PRECISION}"

        return True, "measured precision clears the floor"

    @classmethod
    def record_auto_clear(cls, application):
        _, _, cleared_key = cls.keys(application.id)
        count = int(cache.get(cleared_key) or 0) + 1
        cache.set(cleared_key, count, 2 * 24 * 60 * 60)
        return count

    @classmethod
    def record_override(cls, application, overruled):
        """
        A human disagreed with (or agreed with) an auto-clear after the fact.
        Three disagreements in a row trip the breaker.
        """
        tripped_key, overrides_key, _ = cls.keys(application.id)
        if not overruled:
            cache.delete(overrides_key)
            return 0
        count = int(cache.get(overrides_key) or 0) + 1
        cache.set(overrides_key, count, 30 * 24 * 60 * 60)
        if count >= cls.MAX_CONSECUTIVE_OVERRIDES:
            cache.set(tripped_key, timezone.now().isoformat(), None)
        return count

    @classmethod
    def record_outcome(cls, application, audit_log, label):
        """
        A merchant reported an outcome on a decision. If the case behind it
        was auto-cleared and nobody has looked since, this is the network
        telling us whether the model was right.
        """
        from core.audit.models import AuditLogLabel

        case = getattr(audit_log, "case", None)
        if case is None or not case.triage_auto_closed or case.assignee_id is not None:
            return None
        overruled = label in (AuditLogLabel.FRAUD, AuditLogLabel.CHARGEBACK)
        return cls.record_override(application, overruled=overruled)

    @classmethod
    def reset(cls, application):
        """A person re-enables auto-clearing after a trip."""
        tripped_key, overrides_key, _ = cls.keys(application.id)
        cache.delete_many([tripped_key, overrides_key])

    @classmethod
    def tripped(cls, application):
        tripped_key, _, _ = cls.keys(application.id)
        return cache.get(tripped_key)
