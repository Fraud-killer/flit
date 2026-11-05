import math
from enum import Enum
from uuid import UUID
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import timedelta
from django.utils import timezone

from core.scoring.weights import RiskWeights, RiskThresholds, DEFAULT_WEIGHTS, DEFAULT_THRESHOLDS


# Below this a score is not worth watching. Not a decision threshold, so not
# calibrated; the thresholds that act are on RiskThresholds.
MONITOR_AT = 0.3


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float, thresholds: Optional[RiskThresholds] = None) -> "RiskLevel":
        """
        The level reads from the same thresholds the decision does. A
        calibrated application that blocks at 0.6 reports a 0.65 as critical,
        because that is what it did with it.
        """
        thresholds = thresholds or DEFAULT_THRESHOLDS

        if score >= thresholds.block_at:
            return cls.CRITICAL
        if score >= thresholds.review_at:
            return cls.HIGH
        if score >= min(MONITOR_AT, thresholds.review_at):
            return cls.MEDIUM
        return cls.LOW


@dataclass
class RiskFactor:
    code: str
    weight: float
    score: float
    message: str
    category: str = "general"
    context: Dict[str, Any] = field(default_factory=dict)

    @property
    def weighted_score(self) -> float:
        return self.weight * self.score


@dataclass
class RiskScore:
    total_score: float
    level: RiskLevel
    factors: List[RiskFactor]
    recommendation: str
    should_block: bool
    should_review: bool
    confidence: float
    should_challenge: bool = False
    # How much of the identity signal FLIT expected actually arrived, 0.0–1.0,
    # or None when the caller did not measure it. Reported alongside the score
    # so a thin verdict can be told apart from a well-evidenced one.
    coverage: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.total_score, 4),
            "level": self.level.value,
            "factors": [
                {
                    "code": f.code,
                    "weight": f.weight,
                    "score": f.score,
                    "weighted_score": round(f.weighted_score, 4),
                    "message": f.message,
                    "category": f.category,
                    "context": f.context,
                }
                for f in self.factors
            ],
            "recommendation": self.recommendation,
            "should_block": self.should_block,
            "should_review": self.should_review,
            "should_challenge": self.should_challenge,
            "confidence": round(self.confidence, 4),
            "coverage": self.coverage,
            "metadata": self.metadata,
        }


class RiskEngine:
    # How much of the score a cleared step-up is worth. Enough to take a
    # borderline decision out of the challenge band; not enough to turn a
    # block into an allow.
    CHALLENGE_PASSED_DISCOUNT = 0.4

    def __init__(
        self,
        weights: Optional[RiskWeights] = None,
        thresholds: Optional[RiskThresholds] = None,
    ):
        self.weights = weights or DEFAULT_WEIGHTS
        self.thresholds = thresholds or DEFAULT_THRESHOLDS

    def calculate_risk(
        self,
        rule_messages: List[Dict[str, Any]],
        *,
        event_category: str = "transaction",
        historical_risk_scores: Optional[List[float]] = None,
        device_trust_score: Optional[float] = None,
        account_age_days: Optional[int] = None,
        previous_fraud_count: int = 0,
        coverage: Optional[float] = None,
    ) -> RiskScore:
        factors = []

        for msg in rule_messages:
            code = msg.get("code", "unknown")
            context = msg.get("context") or {}
            weight = self.weights.get_weight(code, default=context.get("score"))

            # `weight` is how much this kind of evidence counts; `severity` is
            # how bad this particular instance is. A rule that grades its own
            # findings sets severity; anything without one is taken at full
            # strength, which is how every rule behaved before.
            base_score = self._severity(context)

            if previous_fraud_count > 0:
                base_score *= (1 + 0.1 * min(previous_fraud_count, 5))

            if account_age_days is not None and account_age_days < 30:
                base_score *= 1.2

            if device_trust_score is not None:
                base_score *= (2 - device_trust_score)

            factor = RiskFactor(
                code=code,
                weight=weight,
                score=min(base_score, 1.0),
                message=msg.get("text", ""),
                category=msg.get("context", {}).get("category", "general"),
                context=msg.get("context", {}),
            )
            factors.append(factor)

        total_score = self._calculate_combined_score(factors, event_category)

        if historical_risk_scores:
            historical_avg = sum(historical_risk_scores) / len(historical_risk_scores)
            total_score = 0.7 * total_score + 0.3 * historical_avg

        total_score = max(0.0, min(1.0, total_score))

        # Two findings sit outside the arithmetic. A hard block — a sanctions
        # hit — is not a risk to be weighed against a clean history: the
        # history is irrelevant to whether the counterparty is listed. And a
        # forced review marks a decision whose evidence is incomplete because
        # a control could not run; the score says nothing about that, so the
        # flag has to.
        hard_blocks = [f.code for f in factors if (f.context or {}).get("hard_block")]
        forced_reviews = [f.code for f in factors if (f.context or {}).get("force_review")]
        forced_challenges = [f.code for f in factors if (f.context or {}).get("force_challenge")]
        allows = [f.code for f in factors if (f.context or {}).get("allow")]
        passed_challenges = [f.code for f in factors if (f.context or {}).get("passed_challenge")]

        # A cleared step-up is worth something: the score it would have
        # challenged on is discounted, and the challenge is not asked again.
        # A hard block is not touched by it.
        if passed_challenges and not hard_blocks:
            total_score *= (1.0 - self.CHALLENGE_PASSED_DISCOUNT)

        if hard_blocks:
            total_score = max(total_score, self.thresholds.block_at)

        level = RiskLevel.from_score(total_score, self.thresholds)
        should_block = bool(hard_blocks) or total_score >= self.thresholds.block_at
        should_review = bool(forced_reviews) or total_score >= self.thresholds.review_at

        # A step-up sits below a block deliberately. At the signup surface the
        # evidence is thin by nature, and blocking on thin evidence costs real
        # customers; a challenge makes the eleventh account cost as much as
        # the first without charging the honest user anything but one puzzle.
        should_challenge = not should_block and (
            bool(forced_challenges) or total_score >= self.thresholds.challenge_at
        )

        # An allow is the weakest instruction here. It waives the review and
        # challenge the *score* asked for; it does not touch a block, and it
        # does not silence a control that did not run.
        if allows and not hard_blocks:
            should_review = bool(forced_reviews)
            should_challenge = False

        if passed_challenges and not hard_blocks:
            should_challenge = False

        recommendation = self._get_recommendation(
            level, factors,
            should_block=should_block,
            should_challenge=should_challenge,
            should_review=should_review,
            forced_reviews=forced_reviews,
        )

        confidence = self._calculate_confidence(factors, historical_risk_scores)

        return RiskScore(
            total_score=total_score,
            level=level,
            factors=factors,
            recommendation=recommendation,
            should_block=should_block,
            should_review=should_review,
            should_challenge=should_challenge,
            confidence=confidence,
            coverage=coverage,
            metadata={
                "factors_count": len(factors),
                "event_category": event_category,
                "has_historical_data": historical_risk_scores is not None,
                "coverage": coverage,
                "hard_blocks": hard_blocks,
                "forced_reviews": forced_reviews,
                "forced_challenges": forced_challenges,
                "allows": allows,
                "passed_challenges": passed_challenges,
            },
        )

    @staticmethod
    def _severity(context: Dict[str, Any]) -> float:
        """
        How bad one finding is, 0.0–1.0, defaulting to full strength.

        Only `severity` is read. A rule's `score` is left alone: it already
        serves as the weight fallback for codes with no configured weight, and
        reusing it here would silently rescale every existing rule.
        """
        severity = context.get("severity")

        if severity is None:
            return 1.0

        try:
            return max(0.0, min(float(severity), 1.0))
        except (TypeError, ValueError):
            return 1.0

    def _calculate_combined_score(
        self,
        factors: List[RiskFactor],
        event_category: str,
    ) -> float:
        # Zero-weight factors (data completeness markers) are reported but
        # are not evidence, so they must not dilute the average either.
        factors = [factor for factor in factors if factor.weight > 0]

        if not factors:
            return 0.0

        category_multiplier = self.weights.category_multipliers.get(event_category, 1.0)

        weighted_scores = [f.weighted_score for f in factors]

        max_score = max(weighted_scores) if weighted_scores else 0
        avg_score = sum(weighted_scores) / len(weighted_scores) if weighted_scores else 0

        combined = 0.6 * max_score + 0.4 * avg_score

        factor_count_boost = 1 + (0.05 * min(len(factors) - 1, 5))
        combined *= factor_count_boost

        combined *= category_multiplier

        return combined

    def _get_recommendation(
        self,
        level: RiskLevel,
        factors: List[RiskFactor],
        *,
        should_block: Optional[bool] = None,
        should_challenge: bool = False,
        should_review: Optional[bool] = None,
        forced_reviews: Optional[List[str]] = None,
    ) -> str:
        # The words follow the flags an integration branches on, so the two
        # can never disagree once thresholds are calibrated.
        if should_block is None:
            should_block = level == RiskLevel.CRITICAL
        if should_review is None:
            should_review = level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

        if should_block:
            return "BLOCK: High-risk activity detected. Recommend blocking transaction and triggering manual review."

        if should_challenge:
            names = ", ".join(f.code for f in sorted(
                factors, key=lambda item: item.weighted_score, reverse=True,
            )[:3])
            return (
                f"CHALLENGE: Step up verification before proceeding ({names})."
                " Evidence is short of a block but the action should cost more than one request."
            )

        if should_review:
            if forced_reviews and level not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                names = ", ".join(forced_reviews[:3])
                return f"REVIEW: A control did not run ({names}). The decision is incomplete and needs a look."
            high_weight_factors = [f for f in factors if f.weight >= 0.7]
            if high_weight_factors:
                factor_names = ", ".join(f.code for f in high_weight_factors[:3])
                return f"REVIEW: Elevated risk due to {factor_names}. Recommend additional verification."
            return "REVIEW: Multiple risk factors detected. Recommend step-up authentication."

        if level == RiskLevel.MEDIUM:
            return "MONITOR: Moderate risk detected. Continue monitoring and log for analysis."

        return "ALLOW: Low risk. Proceed with standard processing."

    def _calculate_confidence(
        self,
        factors: List[RiskFactor],
        historical_data: Optional[List[float]],
    ) -> float:
        base_confidence = 0.5

        if factors:
            base_confidence += 0.1 * min(len(factors), 3)

        if historical_data:
            data_points = len(historical_data)
            base_confidence += 0.05 * min(data_points, 5)

            variance = self._calculate_variance(historical_data)
            if variance < 0.1:
                base_confidence += 0.1

        return min(base_confidence, 1.0)

    @staticmethod
    def _calculate_variance(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return sum((x - mean) ** 2 for x in values) / len(values)

    async def get_historical_scores(
        self,
        actor_id: str,
        application_id: UUID,
        lookback_days: int = 30,
    ) -> List[float]:
        from asgiref.sync import sync_to_async
        from core.audit.models import AuditLog, AuditLogCategory

        lookback_time = timezone.now() - timedelta(days=lookback_days)

        @sync_to_async
        def fetch_scores():
            logs = AuditLog.objects.filter(
                actor_id=actor_id,
                application_id=application_id,
                category=AuditLogCategory.TRANSACTION,
                timestamp__gte=lookback_time,
                risk_score__isnull=False,
            ).values_list("risk_score", flat=True)[:100]

            return list(logs)

        return await fetch_scores()

    async def get_device_trust_score(
        self,
        device_fingerprint: str,
        application_id: UUID,
    ) -> float:
        from asgiref.sync import sync_to_async
        from core.models import Device
        from core.audit.models import AuditLog, AuditLogCategory

        @sync_to_async
        def calculate_trust():
            device = Device.objects.filter(
                fingerprint=device_fingerprint,
                application=application_id,
            ).first()

            if not device:
                return 0.3

            base_trust = 0.5

            age_days = (timezone.now() - device.created_at).days
            if age_days > 90:
                base_trust += 0.2
            elif age_days > 30:
                base_trust += 0.1

            location_count = len(device.locations)
            if location_count == 1:
                base_trust += 0.1
            elif location_count > 5:
                base_trust -= 0.1

            recent_failures = AuditLog.objects.filter(
                device_fingerprint=device_fingerprint,
                application_id=application_id,
                outcome="failure",
                timestamp__gte=timezone.now() - timedelta(days=7),
            ).count()

            if recent_failures > 5:
                base_trust -= 0.2
            elif recent_failures > 0:
                base_trust -= 0.05 * recent_failures

            return max(0.0, min(1.0, base_trust))

        return await calculate_trust()
