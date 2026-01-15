"""
Issuer Signal Detection Rule

Detects and categorizes signals from card issuers that indicate
fraud risk, velocity limits, or other business rules being triggered.
"""

from typing import Any
from .base_rule import BaseRule


class IssuerSignalRule(BaseRule):
    """
    Analyzes issuer decline signals for fraud indicators.
    
    Issuer signals include:
    - Anti-fraud system triggers
    - Business rules violations
    - Velocity limit breaches
    - Card restrictions
    """
    
    name = "Issuer Signal Detection"
    weight = 0.85
    
    # Categorized issuer signals
    FRAUD_SIGNALS = [
        "anti-fraud",
        "antifraud",
        "fraud",
        "suspected fraud",
        "fraudulent",
        "security violation",
        "stolen card",
        "lost card",
        "pickup card",
    ]
    
    VELOCITY_SIGNALS = [
        "business rules",
        "velocity",
        "too many",
        "limit exceeded",
        "daily limit",
        "transaction limit",
        "frequency",
    ]
    
    CARD_ISSUE_SIGNALS = [
        "invalid card",
        "expired card",
        "card not active",
        "restricted card",
        "blocked card",
        "closed account",
        "do not honor",
    ]
    
    AUTHENTICATION_SIGNALS = [
        "3ds",
        "authentication",
        "verification failed",
        "cvv",
        "cvc",
        "security code",
        "pin",
    ]
    
    async def apply(self, event: dict[str, Any], policy: dict[str, Any]) -> None:
        """Analyze issuer signals in the transaction."""
        
        gateway_message = event.get("gateway_message", "")
        provider_responses = event.get("provider_responses", [])
        
        # Analyze main gateway message
        if gateway_message:
            self._analyze_message(gateway_message, "gateway")
        
        # Analyze all provider response messages
        for response in provider_responses:
            if isinstance(response, dict):
                provider_data = response.get("provider_data", {})
                if isinstance(provider_data, dict):
                    message = provider_data.get("message", "")
                    if message:
                        self._analyze_message(message, "provider")
        
        # Track issuer signal patterns for this card
        card_hash = self._get_card_hash(event)
        if card_hash and gateway_message:
            await self._track_issuer_signals(card_hash, gateway_message)
    
    def _analyze_message(self, message: str, source: str) -> None:
        """Analyze a single message for issuer signals."""
        message_lower = message.lower()
        
        # Check for fraud signals (highest severity)
        for signal in self.FRAUD_SIGNALS:
            if signal in message_lower:
                self.add_message(
                    f"Issuer fraud signal detected: '{message}'",
                    severity="critical"
                )
                return
        
        # Check for velocity signals
        for signal in self.VELOCITY_SIGNALS:
            if signal in message_lower:
                self.add_message(
                    f"Issuer velocity/business rules triggered: '{message}'",
                    severity="high"
                )
                return
        
        # Check for card issue signals
        for signal in self.CARD_ISSUE_SIGNALS:
            if signal in message_lower:
                self.add_message(
                    f"Card issue detected by issuer: '{message}'",
                    severity="medium"
                )
                return
        
        # Check for authentication signals
        for signal in self.AUTHENTICATION_SIGNALS:
            if signal in message_lower:
                self.add_message(
                    f"Authentication issue: '{message}'",
                    severity="medium"
                )
                return
    
    def _get_card_hash(self, event: dict) -> str | None:
        """Extract card identifier from event."""
        payment_instrument = event.get("payment_instrument", {})
        if isinstance(payment_instrument, dict):
            card = payment_instrument.get("card", {})
            if isinstance(card, dict):
                return card.get("number", "")
        return None
    
    async def _track_issuer_signals(self, card_hash: str, message: str) -> None:
        """Track issuer signals for pattern detection."""
        from django.core.cache import cache
        
        cache_key = f"issuer_signals:{card_hash}"
        signals = cache.get(cache_key, [])
        
        # Add new signal
        signals.append({
            "message": message,
            "timestamp": str(datetime.utcnow()) if 'datetime' in dir() else "now"
        })
        
        # Keep last 10 signals
        signals = signals[-10:]
        
        # Check for repeated fraud signals
        fraud_count = sum(
            1 for s in signals 
            if any(f in s.get("message", "").lower() for f in self.FRAUD_SIGNALS)
        )
        
        if fraud_count >= 2:
            self.add_message(
                f"Card has {fraud_count} issuer fraud flags - high risk",
                severity="critical"
            )
        
        cache.set(cache_key, signals, timeout=86400)  # 24 hours
