"""
3DS Timeout Detection Rule

Detects patterns where 3DS authentication consistently times out,
which is a strong indicator of automated/bot traffic that cannot
complete human verification challenges.
"""

from typing import Any
from .base_rule import BaseRule


class ThreeDSTimeoutRule(BaseRule):
    """
    Detects 3DS timeout patterns that indicate bot/automation.
    
    Bots cannot complete 3DS challenges because:
    - No human to receive/enter OTP
    - No access to banking app for push notifications
    - Cannot solve visual challenges
    
    High 3DS timeout rates strongly correlate with fraud.
    """
    
    name = "3DS Timeout Detection"
    weight = 0.85
    
    # Thresholds
    TIMEOUT_RATE_THRESHOLD = 0.3  # 30% timeout rate is suspicious
    MIN_ATTEMPTS_FOR_RATE = 3  # Need at least 3 attempts to calculate rate
    
    async def apply(self, event: dict[str, Any], policy: dict[str, Any]) -> None:
        """Check for 3DS timeout patterns."""
        
        # Check current transaction for 3DS timeout
        gateway_message = event.get("gateway_message", "")
        provider_responses = event.get("provider_responses", [])
        
        # Direct 3DS timeout in current transaction
        if self._is_3ds_timeout(gateway_message):
            self.add_message(
                "3DS authentication timed out - possible bot/automation",
                severity="high"
            )
            return
        
        # Check provider responses for 3DS timeout
        for response in provider_responses:
            if isinstance(response, dict):
                provider_data = response.get("provider_data", {})
                if isinstance(provider_data, dict):
                    message = provider_data.get("message", "")
                    if self._is_3ds_timeout(message):
                        self.add_message(
                            "3DS timeout detected in provider response",
                            severity="high"
                        )
                        return
        
        # Check historical 3DS timeout rate for this customer/card
        customer_id = event.get("customer_id")
        card_hash = event.get("card_hash") or self._get_card_hash(event)
        
        if customer_id:
            await self._check_customer_timeout_rate(customer_id)
        
        if card_hash:
            await self._check_card_timeout_rate(card_hash)
    
    def _is_3ds_timeout(self, message: str) -> bool:
        """Check if message indicates 3DS timeout."""
        if not message:
            return False
        
        message_lower = message.lower()
        timeout_indicators = [
            "3ds timeout",
            "3ds_timeout",
            "3d secure timeout",
            "authentication timeout",
            "challenge timeout",
            "otp timeout",
            "verification timeout",
            "cancelled by timeout",
        ]
        
        return any(indicator in message_lower for indicator in timeout_indicators)
    
    def _get_card_hash(self, event: dict) -> str | None:
        """Extract card identifier from event."""
        payment_instrument = event.get("payment_instrument", {})
        if isinstance(payment_instrument, dict):
            card = payment_instrument.get("card", {})
            if isinstance(card, dict):
                # Use masked card number as identifier
                return card.get("number", "")
        return None
    
    async def _check_customer_timeout_rate(self, customer_id: str) -> None:
        """Check historical 3DS timeout rate for customer."""
        # In production, this would query the database
        # For now, we track in cache
        from django.core.cache import cache
        
        cache_key = f"3ds_timeout_rate:customer:{customer_id}"
        timeout_data = cache.get(cache_key, {"timeouts": 0, "attempts": 0})
        
        attempts = timeout_data.get("attempts", 0)
        timeouts = timeout_data.get("timeouts", 0)
        
        if attempts >= self.MIN_ATTEMPTS_FOR_RATE:
            timeout_rate = timeouts / attempts
            if timeout_rate >= self.TIMEOUT_RATE_THRESHOLD:
                self.add_message(
                    f"Customer has {timeout_rate:.0%} 3DS timeout rate "
                    f"({timeouts}/{attempts} attempts) - likely bot",
                    severity="high"
                )
    
    async def _check_card_timeout_rate(self, card_hash: str) -> None:
        """Check historical 3DS timeout rate for card."""
        from django.core.cache import cache
        
        cache_key = f"3ds_timeout_rate:card:{card_hash}"
        timeout_data = cache.get(cache_key, {"timeouts": 0, "attempts": 0})
        
        attempts = timeout_data.get("attempts", 0)
        timeouts = timeout_data.get("timeouts", 0)
        
        if attempts >= self.MIN_ATTEMPTS_FOR_RATE:
            timeout_rate = timeouts / attempts
            if timeout_rate >= self.TIMEOUT_RATE_THRESHOLD:
                self.add_message(
                    f"Card has {timeout_rate:.0%} 3DS timeout rate - likely compromised",
                    severity="high"
                )
