"""
Card Testing Detection Rule

Detects card testing/enumeration attacks based on patterns observed in real payment data:
- Multiple small transactions
- Sequential card numbers
- High failure rates
- Rapid transaction attempts
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from django.core.cache import cache

from core.audit.rules.base_rule import BaseRule


@dataclass
class CardTestingSignal:
    """Card testing indicator."""
    indicator: str
    confidence: float
    details: Dict[str, Any]


class CardTestingRule(BaseRule):
    """
    Detects card testing and enumeration attacks.
    
    Card testing is when fraudsters validate stolen card numbers by making
    small transactions. Patterns include:
    - Multiple small-value transactions
    - High failure rate followed by success
    - Same BIN with different card numbers
    - Rapid sequential attempts
    """

    SMALL_AMOUNT_THRESHOLD = 500  # $5.00 in cents
    TESTING_WINDOW_MINUTES = 30
    MIN_ATTEMPTS_FOR_TESTING = 3
    HIGH_FAILURE_RATE_THRESHOLD = 0.7

    CACHE_PREFIX = "card_testing:"
    CACHE_TTL = 1800  # 30 minutes

    async def execute(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Detect card testing patterns."""
        card_fingerprint = event.get("card_fingerprint", "")
        card_bin = event.get("card_bin", "")  # First 6 digits
        amount = event.get("amount", 0)
        status = event.get("status", "")
        ip_address = event.get("ip_address", "")
        customer_id = event.get("customer_id", "")

        signals: List[CardTestingSignal] = []
        is_card_testing = False
        confidence = 0.0

        # Track this transaction
        if card_fingerprint:
            await self._track_transaction(card_fingerprint, amount, status)

        # Check 1: Small amount pattern
        if amount < self.SMALL_AMOUNT_THRESHOLD:
            small_tx_count = await self._count_small_transactions(ip_address)
            if small_tx_count >= self.MIN_ATTEMPTS_FOR_TESTING:
                signals.append(CardTestingSignal(
                    indicator="multiple_small_transactions",
                    confidence=0.8,
                    details={"count": small_tx_count, "threshold": self.SMALL_AMOUNT_THRESHOLD}
                ))

        # Check 2: High failure rate on this card
        if card_fingerprint:
            failure_rate = await self._get_failure_rate(card_fingerprint)
            if failure_rate >= self.HIGH_FAILURE_RATE_THRESHOLD:
                signals.append(CardTestingSignal(
                    indicator="high_failure_rate",
                    confidence=0.7,
                    details={"failure_rate": failure_rate}
                ))

        # Check 3: BIN enumeration (multiple cards from same BIN)
        if card_bin and ip_address:
            bin_count = await self._count_bin_usage(card_bin, ip_address)
            if bin_count >= 3:
                signals.append(CardTestingSignal(
                    indicator="bin_enumeration",
                    confidence=0.9,
                    details={"bin": card_bin, "card_count": bin_count}
                ))

        # Check 4: Success after multiple failures (validation pattern)
        if status == "success" and card_fingerprint:
            prev_failures = await self._get_previous_failures(card_fingerprint)
            if prev_failures >= 2:
                signals.append(CardTestingSignal(
                    indicator="success_after_failures",
                    confidence=0.85,
                    details={"previous_failures": prev_failures}
                ))

        # Calculate overall confidence
        if signals:
            confidence = max(s.confidence for s in signals)
            is_card_testing = confidence >= 0.7

        return {
            "is_card_testing": is_card_testing,
            "confidence": confidence,
            "signals": [
                {
                    "indicator": s.indicator,
                    "confidence": s.confidence,
                    "details": s.details,
                }
                for s in signals
            ],
            "action": "BLOCK" if is_card_testing else "ALLOW",
            "message": self._generate_message(signals) if signals else "",
        }

    async def _track_transaction(self, card_fingerprint: str, amount: int, status: str):
        """Track transaction for pattern analysis."""
        cache_key = f"{self.CACHE_PREFIX}tx:{card_fingerprint}"
        transactions = cache.get(cache_key, [])

        transactions.append({
            "time": datetime.now().isoformat(),
            "amount": amount,
            "status": status,
        })

        # Keep only recent transactions
        cutoff = datetime.now() - timedelta(minutes=self.TESTING_WINDOW_MINUTES)
        transactions = [
            tx for tx in transactions
            if datetime.fromisoformat(tx["time"]) > cutoff
        ]

        cache.set(cache_key, transactions, self.CACHE_TTL)

    async def _count_small_transactions(self, ip_address: str) -> int:
        """Count small transactions from this IP."""
        cache_key = f"{self.CACHE_PREFIX}small_tx:{ip_address}"
        count = cache.get(cache_key, 0)
        count += 1
        cache.set(cache_key, count, self.CACHE_TTL)
        return count

    async def _get_failure_rate(self, card_fingerprint: str) -> float:
        """Get failure rate for this card."""
        cache_key = f"{self.CACHE_PREFIX}tx:{card_fingerprint}"
        transactions = cache.get(cache_key, [])

        if len(transactions) < 2:
            return 0.0

        failures = sum(1 for tx in transactions if tx["status"] == "failed")
        return failures / len(transactions)

    async def _count_bin_usage(self, card_bin: str, ip_address: str) -> int:
        """Count unique cards from same BIN used by this IP."""
        cache_key = f"{self.CACHE_PREFIX}bin:{ip_address}:{card_bin}"
        cards = cache.get(cache_key, set())
        return len(cards)

    async def _get_previous_failures(self, card_fingerprint: str) -> int:
        """Get count of previous failures for this card."""
        cache_key = f"{self.CACHE_PREFIX}tx:{card_fingerprint}"
        transactions = cache.get(cache_key, [])

        # Count failures before the most recent transaction
        if len(transactions) <= 1:
            return 0

        return sum(1 for tx in transactions[:-1] if tx["status"] == "failed")

    def _generate_message(self, signals: List[CardTestingSignal]) -> str:
        """Generate human-readable message from signals."""
        if not signals:
            return ""

        messages = []
        for signal in signals:
            if signal.indicator == "multiple_small_transactions":
                messages.append(f"Multiple small transactions detected ({signal.details['count']})")
            elif signal.indicator == "high_failure_rate":
                messages.append(f"High failure rate ({signal.details['failure_rate']*100:.0f}%)")
            elif signal.indicator == "bin_enumeration":
                messages.append(f"BIN enumeration: {signal.details['card_count']} cards from BIN {signal.details['bin']}")
            elif signal.indicator == "success_after_failures":
                messages.append(f"Success after {signal.details['previous_failures']} failures")

        return "; ".join(messages)
