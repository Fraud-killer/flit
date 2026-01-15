"""
Retry Attack Detection Rule

Detects rapid retry patterns that indicate card testing or
brute-force attacks on payment systems.
"""

from typing import Any
from datetime import datetime, timedelta
from .base_rule import BaseRule


class RetryAttackRule(BaseRule):
    """
    Detects retry attack patterns commonly used in card testing.
    
    Attack patterns:
    - Same card retried multiple times in quick succession
    - Same customer trying multiple cards rapidly
    - Same IP cycling through many cards
    - Exponential retry patterns (automated)
    """
    
    name = "Retry Attack Detection"
    weight = 0.9
    
    # Thresholds
    MAX_RETRIES_PER_CARD_1MIN = 3
    MAX_RETRIES_PER_CARD_5MIN = 5
    MAX_RETRIES_PER_CARD_1HOUR = 10
    MAX_CARDS_PER_CUSTOMER_1HOUR = 5
    MAX_CARDS_PER_IP_1HOUR = 20
    
    # Time windows
    WINDOW_1MIN = 60
    WINDOW_5MIN = 300
    WINDOW_1HOUR = 3600
    
    async def apply(self, event: dict[str, Any], policy: dict[str, Any]) -> None:
        """Check for retry attack patterns."""
        
        card_hash = self._get_card_hash(event)
        customer_id = event.get("customer_id")
        ip_address = self._get_ip_address(event)
        
        # Check card retry velocity
        if card_hash:
            await self._check_card_retries(card_hash)
        
        # Check customer card cycling
        if customer_id:
            await self._check_customer_card_cycling(customer_id, card_hash)
        
        # Check IP card cycling
        if ip_address:
            await self._check_ip_card_cycling(ip_address, card_hash)
        
        # Check for failure-then-retry pattern
        if card_hash and customer_id:
            await self._check_failure_retry_pattern(card_hash, customer_id)
    
    def _get_card_hash(self, event: dict) -> str | None:
        """Extract card identifier from event."""
        payment_instrument = event.get("payment_instrument", {})
        if isinstance(payment_instrument, dict):
            card = payment_instrument.get("card", {})
            if isinstance(card, dict):
                return card.get("number", "")
        return None
    
    def _get_ip_address(self, event: dict) -> str | None:
        """Extract IP address from event."""
        request_details = event.get("request_details", {})
        if isinstance(request_details, dict):
            return request_details.get("ipAddress")
        return None
    
    async def _check_card_retries(self, card_hash: str) -> None:
        """Check how many times this card has been retried."""
        from django.core.cache import cache
        
        now = datetime.utcnow()
        cache_key = f"card_retries:{card_hash}"
        
        # Get retry history
        retries = cache.get(cache_key, [])
        
        # Filter to recent retries
        retries_1min = [r for r in retries if now - r < timedelta(seconds=self.WINDOW_1MIN)]
        retries_5min = [r for r in retries if now - r < timedelta(seconds=self.WINDOW_5MIN)]
        retries_1hour = [r for r in retries if now - r < timedelta(seconds=self.WINDOW_1HOUR)]
        
        # Check thresholds
        if len(retries_1min) >= self.MAX_RETRIES_PER_CARD_1MIN:
            self.add_message(
                f"Card retried {len(retries_1min)} times in 1 minute - "
                f"likely automated attack",
                severity="critical"
            )
        elif len(retries_5min) >= self.MAX_RETRIES_PER_CARD_5MIN:
            self.add_message(
                f"Card retried {len(retries_5min)} times in 5 minutes - "
                f"suspicious retry pattern",
                severity="high"
            )
        elif len(retries_1hour) >= self.MAX_RETRIES_PER_CARD_1HOUR:
            self.add_message(
                f"Card retried {len(retries_1hour)} times in 1 hour - "
                f"excessive retries",
                severity="medium"
            )
        
        # Update cache with new retry
        retries.append(now)
        # Keep only last hour of retries
        retries = [r for r in retries if now - r < timedelta(seconds=self.WINDOW_1HOUR)]
        cache.set(cache_key, retries, timeout=self.WINDOW_1HOUR)
    
    async def _check_customer_card_cycling(
        self, customer_id: str, current_card: str | None
    ) -> None:
        """Check if customer is cycling through multiple cards."""
        from django.core.cache import cache
        
        if not current_card:
            return
        
        cache_key = f"customer_cards:{customer_id}"
        cards_used = cache.get(cache_key, set())
        
        # Add current card
        cards_used.add(current_card)
        
        if len(cards_used) >= self.MAX_CARDS_PER_CUSTOMER_1HOUR:
            self.add_message(
                f"Customer used {len(cards_used)} different cards in 1 hour - "
                f"possible card testing",
                severity="high"
            )
        
        cache.set(cache_key, cards_used, timeout=self.WINDOW_1HOUR)
    
    async def _check_ip_card_cycling(
        self, ip_address: str, current_card: str | None
    ) -> None:
        """Check if IP is cycling through multiple cards."""
        from django.core.cache import cache
        
        if not current_card:
            return
        
        cache_key = f"ip_cards:{ip_address}"
        cards_used = cache.get(cache_key, set())
        
        # Add current card
        cards_used.add(current_card)
        
        if len(cards_used) >= self.MAX_CARDS_PER_IP_1HOUR:
            self.add_message(
                f"IP {ip_address} used {len(cards_used)} different cards in 1 hour - "
                f"likely card testing operation",
                severity="critical"
            )
        
        cache.set(cache_key, cards_used, timeout=self.WINDOW_1HOUR)
    
    async def _check_failure_retry_pattern(
        self, card_hash: str, customer_id: str
    ) -> None:
        """Check for pattern of failures followed by retries."""
        from django.core.cache import cache
        
        cache_key = f"failure_pattern:{card_hash}:{customer_id}"
        pattern = cache.get(cache_key, {"failures": 0, "last_failure": None})
        
        failures = pattern.get("failures", 0)
        
        # If there have been multiple recent failures, flag the retry
        if failures >= 3:
            self.add_message(
                f"Retry after {failures} consecutive failures - "
                f"persistent attack pattern",
                severity="high"
            )
