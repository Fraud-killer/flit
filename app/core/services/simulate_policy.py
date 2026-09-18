"""
Replays recorded decisions under candidate weights and thresholds.

Merchants tune fraud rules by guessing and waiting for complaints. Because
every audit keeps its factors, FLIT can answer the question directly: if this
threshold had been 0.6 last month, what would it have caught, and who would
it have blocked by mistake?

Baseline and candidate are both recomputed the same way, so the comparison is
exact even where a recomputed score differs slightly from the recorded one
(historical blending at decision time is not reproducible from the log).
"""

from datetime import timedelta
from django.utils import timezone

from core.models import AuditLog
from core.audit.models import AuditLogLabel
from core.scoring import RiskEngine, RiskWeights, RiskThresholds, DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS
from core.scoring.risk_engine import RiskFactor, RiskLevel


FRAUD_LABELS = {AuditLogLabel.FRAUD, AuditLogLabel.CHARGEBACK}
LEGIT_LABELS = {AuditLogLabel.LEGIT, AuditLogLabel.FALSE_POSITIVE}


class SimulatePolicy:
    DEFAULT_DAYS = 30
    MAX_DECISIONS = 20000
    SAMPLE_SIZE = 10

    @classmethod
    def call(cls, *, application, weights=None, thresholds=None, days=DEFAULT_DAYS):
        since = timezone.now() - timedelta(days=days)

        decisions = list(
            AuditLog.objects
            .filter(application_id=application.id, timestamp__gte=since)
            .order_by("-timestamp")[:cls.MAX_DECISIONS]
        )

        baseline_engine = RiskEngine(DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS)
        candidate_engine = RiskEngine(
            cls.merge_weights(weights),
            cls.merge_thresholds(thresholds),
        )

        approximated = 0
        rows = []

        for decision in decisions:
            factors, exact = cls.factors_for(decision)
            if not exact:
                approximated += 1

            rows.append(dict(
                decision=decision,
                baseline=cls.score(baseline_engine, decision, factors),
                candidate=cls.score(candidate_engine, decision, factors),
            ))

        return dict(
            window_days=days,
            decisions=len(rows),
            labelled=sum(1 for row in rows if row["decision"].label),
            # Rows recorded before factor detail was kept are re-scored from
            # codes alone, assuming an unmodified factor score.
            approximated_decisions=approximated,
            thresholds=cls.describe_thresholds(candidate_engine.thresholds),
            baseline=cls.summarize(rows, "baseline"),
            candidate=cls.summarize(rows, "candidate"),
            changes=cls.changes(rows),
        )

    @classmethod
    def merge_weights(cls, weights):
        if not weights:
            return DEFAULT_WEIGHTS

        merged = RiskWeights()

        for code, value in weights.items():
            value = float(value)

            # Named weights are set on the field; anything else (a message
            # code with no field of its own) goes through overrides.
            if hasattr(merged, code):
                setattr(merged, code, value)
            else:
                merged.overrides[code] = value

        return merged

    @classmethod
    def merge_thresholds(cls, thresholds):
        if not thresholds:
            return DEFAULT_THRESHOLDS

        return RiskThresholds(
            block_at=float(thresholds.get("block_at", DEFAULT_THRESHOLDS.block_at)),
            review_at=float(thresholds.get("review_at", DEFAULT_THRESHOLDS.review_at)),
        )

    @classmethod
    def factors_for(cls, decision):
        """(factor dicts, whether the stored detail was exact)."""
        stored = (decision.context or {}).get("factors")

        if stored:
            return stored, True

        return [dict(code=code, score=1.0) for code in decision.risk_factors or []], False

    @classmethod
    def score(cls, engine, decision, factors):
        risk_factors = [
            RiskFactor(
                code=factor["code"],
                weight=engine.weights.get_weight(factor["code"], default=factor.get("weight")),
                score=factor.get("score", 1.0),
                message="",
            )
            for factor in factors
        ]

        total = engine._calculate_combined_score(risk_factors, decision.category)
        total = max(0.0, min(1.0, total))

        return dict(
            score=total,
            level=RiskLevel.from_score(total).value,
            blocked=total >= engine.thresholds.block_at,
            reviewed=total >= engine.thresholds.review_at,
        )

    @classmethod
    def summarize(cls, rows, key):
        blocked = [row for row in rows if row[key]["blocked"]]
        reviewed = [row for row in rows if row[key]["reviewed"]]

        caught = sum(1 for row in blocked if cls.is_fraud(row["decision"]))
        false_positives = sum(1 for row in blocked if cls.is_legit(row["decision"]))
        fraud_total = sum(1 for row in rows if cls.is_fraud(row["decision"]))

        return dict(
            blocked=len(blocked),
            reviewed=len(reviewed),
            caught_fraud=caught,
            missed_fraud=fraud_total - caught,
            false_positives=false_positives,
            precision=cls.ratio(caught, caught + false_positives),
            recall=cls.ratio(caught, fraud_total),
        )

    @classmethod
    def changes(cls, rows):
        newly_blocked = [row for row in rows if row["candidate"]["blocked"] and not row["baseline"]["blocked"]]
        newly_allowed = [row for row in rows if row["baseline"]["blocked"] and not row["candidate"]["blocked"]]

        return dict(
            newly_blocked=len(newly_blocked),
            newly_allowed=len(newly_allowed),
            newly_blocked_fraud=sum(1 for row in newly_blocked if cls.is_fraud(row["decision"])),
            newly_blocked_legit=sum(1 for row in newly_blocked if cls.is_legit(row["decision"])),
            newly_allowed_fraud=sum(1 for row in newly_allowed if cls.is_fraud(row["decision"])),
            newly_allowed_legit=sum(1 for row in newly_allowed if cls.is_legit(row["decision"])),
            newly_blocked_sample=cls.sample(newly_blocked),
            newly_allowed_sample=cls.sample(newly_allowed),
        )

    @classmethod
    def sample(cls, rows):
        return [
            dict(
                audit_id=str(row["decision"].id),
                event_id=row["decision"].resource_id,
                client_id=row["decision"].actor_id,
                label=row["decision"].label,
                baseline_score=round(row["baseline"]["score"], 4),
                candidate_score=round(row["candidate"]["score"], 4),
                factors=row["decision"].risk_factors,
            )
            for row in rows[:cls.SAMPLE_SIZE]
        ]

    @staticmethod
    def describe_thresholds(thresholds):
        return dict(block_at=thresholds.block_at, review_at=thresholds.review_at)

    @staticmethod
    def is_fraud(decision):
        return decision.label in FRAUD_LABELS

    @staticmethod
    def is_legit(decision):
        return decision.label in LEGIT_LABELS

    @staticmethod
    def ratio(numerator, denominator):
        return round(numerator / denominator, 4) if denominator else None
