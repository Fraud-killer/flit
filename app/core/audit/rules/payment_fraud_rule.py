"""
Payment Fraud Detection Rule

Enhanced fraud detection based on real-world payment data patterns:
- Automated client detection (Faraday, curl, etc.)
- Headless browser fingerprinting
- IP concentration analysis
- Rapid retry detection
- Card velocity monitoring
- Gateway decline pattern analysis
"""

import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from collections import defaultdict

from django.core.cache import cache

from core.audit.rules.base_rule import BaseRule


@dataclass
class PaymentFraudSignal:
    """Individual fraud signal detected."""
    code: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    score: float  # 0.0 to 1.0
    message: str
    details: Dict[str, Any]


class PaymentFraudRule(BaseRule):
    """
    Detects payment fraud patterns based on real-world attack data.
    
    This rule analyzes:
    1. Browser/client fingerprints for automation
    2. IP address patterns and concentration
    3. Card usage velocity and retry patterns
    4. Gateway decline reasons
    5. Billing/shipping address anomalies
    """

    AUTOMATED_CLIENTS = [
        r"^Faraday",
        r"^curl/",
        r"^python-requests",
        r"^axios/",
        r"^node-fetch",
        r"^Go-http-client",
        r"^Java/",
        r"^okhttp",
        r"^PostmanRuntime",
        r"^insomnia",
        r"^httpie",
        r"^wget",
        r"^libwww-perl",
        r"^PHP/",
    ]

    HEADLESS_INDICATORS = {
        "screen_dimensions": [(480, 640), (800, 600), (1024, 768)],
        "color_depths": [0, 1],
        "timezone_offset": 0,
    }

    HIGH_RISK_GATEWAY_MESSAGES = [
        "anti-fraud",
        "fraud",
        "suspicious",
        "velocity",
        "blocked",
        "blacklist",
        "stolen",
        "lost card",
    ]

    MEDIUM_RISK_GATEWAY_MESSAGES = [
        "business rules",
        "declined by issuer",
        "do not honor",
        "restricted card",
        "exceeds limit",
    ]

    CARD_VELOCITY_LIMITS = {
        "per_minute": 2,
        "per_hour": 10,
        "per_day": 30,
    }

    IP_VELOCITY_LIMITS = {
        "per_minute": 5,
        "per_hour": 50,
        "per_day": 200,
    }

    CACHE_PREFIX = "payment_fraud:"
    CACHE_TTL = 86400  # 24 hours

    async def execute(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Execute payment fraud detection."""
        signals: List[PaymentFraudSignal] = []
        
        # Extract event data
        browser_details = event.get("browser_details", {})
        user_agent = browser_details.get("user_agent", "")
        ip_address = event.get("ip_address", "")
        card_fingerprint = event.get("card_fingerprint", "")
        amount = event.get("amount", 0)
        gateway_message = event.get("gateway_message", "")
        billing = event.get("billing", {})
        shipping = event.get("shipping", {})
        customer_id = event.get("customer_id", "")
        
        # Check 1: Automated client detection
        automation_signal = self._check_automated_client(user_agent)
        if automation_signal:
            signals.append(automation_signal)

        # Check 2: Headless browser detection
        headless_signal = self._check_headless_browser(browser_details)
        if headless_signal:
            signals.append(headless_signal)

        # Check 3: JavaScript disabled
        if browser_details.get("javascript_enabled") == False:
            signals.append(PaymentFraudSignal(
                code="javascript_disabled",
                severity="MEDIUM",
                score=0.4,
                message="JavaScript disabled - unusual for legitimate users",
                details={"javascript_enabled": False}
            ))

        # Check 4: Card velocity
        if card_fingerprint:
            velocity_signals = await self._check_card_velocity(card_fingerprint)
            signals.extend(velocity_signals)

        # Check 5: IP velocity
        if ip_address:
            ip_signals = await self._check_ip_velocity(ip_address)
            signals.extend(ip_signals)

        # Check 6: Gateway message analysis
        gateway_signals = self._analyze_gateway_message(gateway_message)
        signals.extend(gateway_signals)

        # Check 7: Address anomalies
        address_signals = self._check_address_anomalies(billing, shipping)
        signals.extend(address_signals)

        # Check 8: Rapid retry detection
        if card_fingerprint:
            retry_signal = await self._check_rapid_retry(card_fingerprint, customer_id)
            if retry_signal:
                signals.append(retry_signal)

        # Calculate aggregate risk
        total_score = self._calculate_total_score(signals)
        risk_level = self._determine_risk_level(total_score)

        return {
            "signals": [
                {
                    "code": s.code,
                    "severity": s.severity,
                    "score": s.score,
                    "message": s.message,
                    "details": s.details,
                }
                for s in signals
            ],
            "total_score": total_score,
            "risk_level": risk_level,
            "should_block": risk_level in ["HIGH", "CRITICAL"],
            "requires_review": risk_level == "MEDIUM",
        }

    def _check_automated_client(self, user_agent: str) -> Optional[PaymentFraudSignal]:
        """Detect automated HTTP clients."""
        if not user_agent:
            return PaymentFraudSignal(
                code="missing_user_agent",
                severity="HIGH",
                score=0.7,
                message="Missing User-Agent header",
                details={}
            )

        for pattern in self.AUTOMATED_CLIENTS:
            if re.match(pattern, user_agent, re.IGNORECASE):
                return PaymentFraudSignal(
                    code="automated_client",
                    severity="CRITICAL",
                    score=0.95,
                    message=f"Automated HTTP client detected: {user_agent[:50]}",
                    details={"user_agent": user_agent, "pattern": pattern}
                )

        return None

    def _check_headless_browser(self, browser_details: Dict) -> Optional[PaymentFraudSignal]:
        """Detect headless browser indicators."""
        indicators = []

        # Check screen dimensions
        width = browser_details.get("screen_width", 0)
        height = browser_details.get("screen_height", 0)
        if (width, height) in self.HEADLESS_INDICATORS["screen_dimensions"]:
            indicators.append(f"suspicious_screen:{width}x{height}")

        # Check color depth
        color_depth = browser_details.get("color_depth", 24)
        if color_depth in self.HEADLESS_INDICATORS["color_depths"]:
            indicators.append(f"suspicious_color_depth:{color_depth}")

        # Check for missing standard properties
        if not browser_details.get("language"):
            indicators.append("missing_language")

        # Check for Java enabled (usually false in headless)
        if browser_details.get("java_enabled") == False and \
           browser_details.get("javascript_enabled") == False:
            indicators.append("all_plugins_disabled")

        if len(indicators) >= 2:
            return PaymentFraudSignal(
                code="headless_browser",
                severity="HIGH",
                score=0.8,
                message=f"Headless browser indicators: {', '.join(indicators)}",
                details={"indicators": indicators, "browser_details": browser_details}
            )

        return None

    async def _check_card_velocity(self, card_fingerprint: str) -> List[PaymentFraudSignal]:
        """Check card usage velocity."""
        signals = []
        now = datetime.now()

        # Get recent transactions for this card
        cache_key = f"{self.CACHE_PREFIX}card:{card_fingerprint}"
        recent_txs = cache.get(cache_key, [])

        # Add current transaction
        recent_txs.append(now.isoformat())

        # Clean old entries (keep last 24 hours)
        cutoff = now - timedelta(hours=24)
        recent_txs = [ts for ts in recent_txs if datetime.fromisoformat(ts) > cutoff]

        # Save back to cache
        cache.set(cache_key, recent_txs, self.CACHE_TTL)

        # Check velocity limits
        one_minute_ago = now - timedelta(minutes=1)
        one_hour_ago = now - timedelta(hours=1)

        txs_last_minute = sum(1 for ts in recent_txs if datetime.fromisoformat(ts) > one_minute_ago)
        txs_last_hour = sum(1 for ts in recent_txs if datetime.fromisoformat(ts) > one_hour_ago)
        txs_last_day = len(recent_txs)

        if txs_last_minute > self.CARD_VELOCITY_LIMITS["per_minute"]:
            signals.append(PaymentFraudSignal(
                code="card_velocity_minute",
                severity="CRITICAL",
                score=0.95,
                message=f"Card used {txs_last_minute} times in last minute",
                details={"count": txs_last_minute, "limit": self.CARD_VELOCITY_LIMITS["per_minute"]}
            ))

        if txs_last_hour > self.CARD_VELOCITY_LIMITS["per_hour"]:
            signals.append(PaymentFraudSignal(
                code="card_velocity_hour",
                severity="HIGH",
                score=0.8,
                message=f"Card used {txs_last_hour} times in last hour",
                details={"count": txs_last_hour, "limit": self.CARD_VELOCITY_LIMITS["per_hour"]}
            ))

        if txs_last_day > self.CARD_VELOCITY_LIMITS["per_day"]:
            signals.append(PaymentFraudSignal(
                code="card_velocity_day",
                severity="MEDIUM",
                score=0.5,
                message=f"Card used {txs_last_day} times in last 24 hours",
                details={"count": txs_last_day, "limit": self.CARD_VELOCITY_LIMITS["per_day"]}
            ))

        return signals

    async def _check_ip_velocity(self, ip_address: str) -> List[PaymentFraudSignal]:
        """Check IP address transaction velocity."""
        signals = []
        now = datetime.now()

        cache_key = f"{self.CACHE_PREFIX}ip:{ip_address}"
        recent_txs = cache.get(cache_key, [])

        recent_txs.append(now.isoformat())

        cutoff = now - timedelta(hours=24)
        recent_txs = [ts for ts in recent_txs if datetime.fromisoformat(ts) > cutoff]

        cache.set(cache_key, recent_txs, self.CACHE_TTL)

        one_minute_ago = now - timedelta(minutes=1)
        one_hour_ago = now - timedelta(hours=1)

        txs_last_minute = sum(1 for ts in recent_txs if datetime.fromisoformat(ts) > one_minute_ago)
        txs_last_hour = sum(1 for ts in recent_txs if datetime.fromisoformat(ts) > one_hour_ago)

        if txs_last_minute > self.IP_VELOCITY_LIMITS["per_minute"]:
            signals.append(PaymentFraudSignal(
                code="ip_velocity_minute",
                severity="HIGH",
                score=0.85,
                message=f"IP {ip_address} used for {txs_last_minute} transactions in last minute",
                details={"ip": ip_address, "count": txs_last_minute}
            ))

        if txs_last_hour > self.IP_VELOCITY_LIMITS["per_hour"]:
            signals.append(PaymentFraudSignal(
                code="ip_velocity_hour",
                severity="MEDIUM",
                score=0.6,
                message=f"IP {ip_address} used for {txs_last_hour} transactions in last hour",
                details={"ip": ip_address, "count": txs_last_hour}
            ))

        return signals

    def _analyze_gateway_message(self, gateway_message: str) -> List[PaymentFraudSignal]:
        """Analyze gateway decline messages for fraud indicators."""
        signals = []
        message_lower = gateway_message.lower()

        for keyword in self.HIGH_RISK_GATEWAY_MESSAGES:
            if keyword in message_lower:
                signals.append(PaymentFraudSignal(
                    code="gateway_fraud_flag",
                    severity="HIGH",
                    score=0.85,
                    message=f"Gateway flagged as fraud-related: {gateway_message}",
                    details={"gateway_message": gateway_message, "keyword": keyword}
                ))
                break

        for keyword in self.MEDIUM_RISK_GATEWAY_MESSAGES:
            if keyword in message_lower:
                signals.append(PaymentFraudSignal(
                    code="gateway_decline_pattern",
                    severity="MEDIUM",
                    score=0.5,
                    message=f"Gateway decline pattern: {gateway_message}",
                    details={"gateway_message": gateway_message, "keyword": keyword}
                ))
                break

        return signals

    def _check_address_anomalies(self, billing: Dict, shipping: Dict) -> List[PaymentFraudSignal]:
        """Check for address-related fraud indicators."""
        signals = []

        # Check for placeholder/missing addresses
        placeholder_values = {"NA", "N/A", "NONE", "TEST", "XXX", "123"}
        
        billing_city = str(billing.get("city", "")).upper()
        billing_address = str(billing.get("address1", "")).upper()

        if billing_city in placeholder_values or billing_address in placeholder_values:
            signals.append(PaymentFraudSignal(
                code="placeholder_address",
                severity="MEDIUM",
                score=0.5,
                message="Placeholder or missing billing address detected",
                details={"billing": billing}
            ))

        # Check for billing/shipping mismatch
        if billing.get("city") and shipping.get("city"):
            if billing.get("city") != shipping.get("city"):
                signals.append(PaymentFraudSignal(
                    code="address_mismatch",
                    severity="LOW",
                    score=0.2,
                    message=f"Billing city ({billing.get('city')}) differs from shipping ({shipping.get('city')})",
                    details={"billing_city": billing.get("city"), "shipping_city": shipping.get("city")}
                ))

        # Check for country mismatch
        if billing.get("country") and shipping.get("country"):
            if billing.get("country") != shipping.get("country"):
                signals.append(PaymentFraudSignal(
                    code="country_mismatch",
                    severity="MEDIUM",
                    score=0.4,
                    message=f"Billing country ({billing.get('country')}) differs from shipping ({shipping.get('country')})",
                    details={"billing_country": billing.get("country"), "shipping_country": shipping.get("country")}
                ))

        return signals

    async def _check_rapid_retry(self, card_fingerprint: str, customer_id: str) -> Optional[PaymentFraudSignal]:
        """Detect rapid retry after failure."""
        cache_key = f"{self.CACHE_PREFIX}last_failure:{card_fingerprint}"
        last_failure = cache.get(cache_key)

        if last_failure:
            last_failure_time = datetime.fromisoformat(last_failure["time"])
            seconds_since = (datetime.now() - last_failure_time).total_seconds()

            if seconds_since < 60:  # Retry within 1 minute
                return PaymentFraudSignal(
                    code="rapid_retry",
                    severity="HIGH",
                    score=0.7,
                    message=f"Rapid retry {seconds_since:.0f}s after failure",
                    details={
                        "seconds_since_failure": seconds_since,
                        "previous_failure_reason": last_failure.get("reason", "unknown")
                    }
                )

        return None

    def _calculate_total_score(self, signals: List[PaymentFraudSignal]) -> float:
        """Calculate aggregate risk score."""
        if not signals:
            return 0.0

        # Use weighted combination - highest signals matter most
        scores = sorted([s.score for s in signals], reverse=True)
        
        # Diminishing returns for additional signals
        total = 0.0
        for i, score in enumerate(scores):
            weight = 1.0 / (i + 1)  # 1, 0.5, 0.33, 0.25...
            total += score * weight

        # Normalize to 0-1 range
        return min(total / 2, 1.0)

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
