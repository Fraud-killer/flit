"""
Gateway Decline Pattern Analysis Rule

Analyzes patterns in gateway decline messages to identify:
- Issuer-level fraud flags
- Card testing patterns
- Velocity-related declines
- Terminal/configuration issues
"""

from typing import Any, Dict, List
from dataclasses import dataclass
from collections import defaultdict

from django.core.cache import cache

from core.audit.rules.base_rule import BaseRule


@dataclass
class DeclinePattern:
    """Represents a decline pattern category."""
    category: str
    risk_score: float
    action: str  # BLOCK, REVIEW, MONITOR, ALLOW
    message: str


class GatewayPatternRule(BaseRule):
    """
    Analyzes gateway decline patterns to identify fraud and operational issues.
    
    Based on real-world payment data analysis showing common decline reasons:
    - "Declined by Issuer" - Generic issuer decline
    - "Declined by Issuer: Business Rules" - Velocity/limit issues
    - "Declined by Issuer: Anti-fraud" - Issuer fraud detection
    - "Insufficient Funds" - Legitimate decline
    - "Terminal not Found" - Configuration issue
    - "3DS Timeout" - User abandonment or bot
    - "Cancelled by Timeout" - Session timeout
    - "Acquirer Malfunction" - System issue
    """

    DECLINE_PATTERNS = {
        # High-risk fraud indicators
        "anti-fraud": DeclinePattern(
            category="issuer_fraud",
            risk_score=0.9,
            action="BLOCK",
            message="Issuer anti-fraud system triggered"
        ),
        "fraud": DeclinePattern(
            category="fraud_flag",
            risk_score=0.85,
            action="BLOCK",
            message="Transaction flagged as fraudulent"
        ),
        "stolen": DeclinePattern(
            category="stolen_card",
            risk_score=0.95,
            action="BLOCK",
            message="Card reported as stolen"
        ),
        "lost card": DeclinePattern(
            category="lost_card",
            risk_score=0.95,
            action="BLOCK",
            message="Card reported as lost"
        ),
        
        # Medium-risk patterns
        "business rules": DeclinePattern(
            category="velocity_limit",
            risk_score=0.6,
            action="REVIEW",
            message="Issuer business rules triggered (likely velocity)"
        ),
        "do not honor": DeclinePattern(
            category="do_not_honor",
            risk_score=0.5,
            action="REVIEW",
            message="Generic issuer decline - may indicate fraud history"
        ),
        "declined by issuer": DeclinePattern(
            category="issuer_decline",
            risk_score=0.4,
            action="MONITOR",
            message="Generic issuer decline"
        ),
        "restricted card": DeclinePattern(
            category="restricted",
            risk_score=0.6,
            action="REVIEW",
            message="Card has restrictions"
        ),
        
        # Low-risk / legitimate declines
        "insufficient funds": DeclinePattern(
            category="nsf",
            risk_score=0.1,
            action="ALLOW",
            message="Insufficient funds - legitimate decline"
        ),
        "expired card": DeclinePattern(
            category="expired",
            risk_score=0.1,
            action="ALLOW",
            message="Card expired"
        ),
        "invalid card": DeclinePattern(
            category="invalid",
            risk_score=0.3,
            action="MONITOR",
            message="Invalid card number"
        ),
        
        # Timeout patterns (often bots)
        "3ds timeout": DeclinePattern(
            category="3ds_timeout",
            risk_score=0.7,
            action="REVIEW",
            message="3DS challenge timed out - possible bot or card testing"
        ),
        "cancelled by timeout": DeclinePattern(
            category="session_timeout",
            risk_score=0.5,
            action="MONITOR",
            message="Session timed out"
        ),
        
        # System issues
        "terminal not found": DeclinePattern(
            category="config_error",
            risk_score=0.0,
            action="ALLOW",
            message="Terminal configuration issue - not fraud"
        ),
        "acquirer malfunction": DeclinePattern(
            category="system_error",
            risk_score=0.0,
            action="ALLOW",
            message="Acquirer system issue - not fraud"
        ),
    }

    CACHE_PREFIX = "gateway_pattern:"
    CACHE_TTL = 3600  # 1 hour

    async def execute(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze gateway decline patterns."""
        gateway_message = event.get("gateway_message", "")
        card_fingerprint = event.get("card_fingerprint", "")
        customer_id = event.get("customer_id", "")
        status = event.get("status", "")

        result = {
            "pattern": None,
            "risk_score": 0.0,
            "action": "ALLOW",
            "message": "",
            "decline_history": {},
        }

        if status != "failed" or not gateway_message:
            return result

        # Match decline pattern
        message_lower = gateway_message.lower()
        matched_pattern = None

        for keyword, pattern in self.DECLINE_PATTERNS.items():
            if keyword in message_lower:
                matched_pattern = pattern
                break

        if matched_pattern:
            result["pattern"] = matched_pattern.category
            result["risk_score"] = matched_pattern.risk_score
            result["action"] = matched_pattern.action
            result["message"] = matched_pattern.message

        # Track decline history for this card
        if card_fingerprint:
            history = await self._update_decline_history(
                card_fingerprint,
                matched_pattern.category if matched_pattern else "unknown",
                gateway_message
            )
            result["decline_history"] = history

            # Escalate if multiple fraud-related declines
            fraud_declines = history.get("fraud_related", 0)
            if fraud_declines >= 2:
                result["risk_score"] = max(result["risk_score"], 0.9)
                result["action"] = "BLOCK"
                result["message"] = f"Multiple fraud-related declines ({fraud_declines})"

        return result

    async def _update_decline_history(
        self,
        card_fingerprint: str,
        category: str,
        message: str
    ) -> Dict[str, Any]:
        """Track decline history for a card."""
        cache_key = f"{self.CACHE_PREFIX}history:{card_fingerprint}"
        history = cache.get(cache_key, {
            "total_declines": 0,
            "fraud_related": 0,
            "velocity_related": 0,
            "nsf": 0,
            "other": 0,
            "last_decline": None,
            "categories": [],
        })

        history["total_declines"] += 1
        history["last_decline"] = message
        history["categories"].append(category)

        # Categorize
        if category in ["issuer_fraud", "fraud_flag", "stolen_card", "lost_card"]:
            history["fraud_related"] += 1
        elif category in ["velocity_limit", "do_not_honor"]:
            history["velocity_related"] += 1
        elif category == "nsf":
            history["nsf"] += 1
        else:
            history["other"] += 1

        # Keep only last 10 categories
        history["categories"] = history["categories"][-10:]

        cache.set(cache_key, history, self.CACHE_TTL)
        return history
