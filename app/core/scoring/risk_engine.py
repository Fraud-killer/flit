import math
from enum import Enum
from uuid import UUID
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import timedelta
from django.utils import timezone

from core.scoring.weights import RiskWeights, DEFAULT_WEIGHTS


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        if score < 0.3:
            return cls.LOW
        elif score < 0.5:
            return cls.MEDIUM
        elif score < 0.7:
            return cls.HIGH
        else:
            return cls.CRITICAL


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
            "confidence": round(self.confidence, 4),
            "metadata": self.metadata,
        }


class RiskEngine:
    def __init__(self, weights: Optional[RiskWeights] = None):
        self.weights = weights or DEFAULT_WEIGHTS

    def calculate_risk(
        self,
        rule_messages: List[Dict[str, Any]],
        *,
        event_category: str = "transaction",
        historical_risk_scores: Optional[List[float]] = None,
        device_trust_score: Optional[float] = None,
        account_age_days: Optional[int] = None,
        previous_fraud_count: int = 0,
    ) -> RiskScore:
        factors = []

        for msg in rule_messages:
            code = msg.get("code", "unknown")
            weight = self.weights.get_weight(code)

            base_score = 1.0

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

        level = RiskLevel.from_score(total_score)
        recommendation = self._get_recommendation(level, factors)
        should_block = level == RiskLevel.CRITICAL or total_score >= 0.85
        should_review = level in [RiskLevel.HIGH, RiskLevel.CRITICAL] or total_score >= 0.5

        confidence = self._calculate_confidence(factors, historical_risk_scores)

        return RiskScore(
            total_score=total_score,
            level=level,
            factors=factors,
            recommendation=recommendation,
            should_block=should_block,
            should_review=should_review,
            confidence=confidence,
            metadata={
                "factors_count": len(factors),
                "event_category": event_category,
                "has_historical_data": historical_risk_scores is not None,
            },
        )

    def _calculate_combined_score(
        self,
        factors: List[RiskFactor],
        event_category: str,
    ) -> float:
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

    def _get_recommendation(self, level: RiskLevel, factors: List[RiskFactor]) -> str:
        if level == RiskLevel.CRITICAL:
            return "BLOCK: High-risk activity detected. Recommend blocking transaction and triggering manual review."

        if level == RiskLevel.HIGH:
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
