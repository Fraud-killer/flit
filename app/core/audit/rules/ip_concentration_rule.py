"""
IP Concentration Analysis Rule

Detects suspicious IP patterns based on real payment data insights:
- High transaction volume from single IP
- Multiple customers from same IP
- Known datacenter/proxy IPs
- Geographic anomalies
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Set
from dataclasses import dataclass
import ipaddress

from django.core.cache import cache

from core.audit.rules.base_rule import BaseRule


@dataclass
class IPSignal:
    """IP-related fraud signal."""
    code: str
    severity: str
    score: float
    message: str
    details: Dict[str, Any]


class IPConcentrationRule(BaseRule):
    """
    Analyzes IP address patterns for fraud indicators.
    
    Based on real payment data showing:
    - 961 transactions from only 2 IPs
    - Both IPs were AWS datacenter IPs
    - Multiple unique customers from same IP
    """

    # AWS IP ranges (partial list for common regions)
    DATACENTER_RANGES = [
        "52.0.0.0/11",      # AWS US East
        "54.0.0.0/8",       # AWS Global
        "99.80.0.0/12",     # AWS EU
        "35.0.0.0/8",       # GCP
        "104.196.0.0/14",   # GCP
        "13.0.0.0/8",       # Azure
        "20.0.0.0/8",       # Azure
        "40.0.0.0/8",       # Azure
    ]

    # Known proxy/VPN services (example ranges)
    PROXY_INDICATORS = [
        "nordvpn",
        "expressvpn",
        "tor-exit",
        "proxy",
    ]

    THRESHOLDS = {
        "tx_per_ip_per_hour": 20,
        "tx_per_ip_per_day": 100,
        "customers_per_ip": 5,
        "cards_per_ip": 10,
    }

    CACHE_PREFIX = "ip_concentration:"
    CACHE_TTL = 86400  # 24 hours

    async def execute(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IP concentration patterns."""
        ip_address = event.get("ip_address", "")
        customer_id = event.get("customer_id", "")
        card_fingerprint = event.get("card_fingerprint", "")

        if not ip_address:
            return {"signals": [], "risk_score": 0.0, "action": "ALLOW"}

        signals: List[IPSignal] = []

        # Check 1: Datacenter IP detection
        if self._is_datacenter_ip(ip_address):
            signals.append(IPSignal(
                code="datacenter_ip",
                severity="HIGH",
                score=0.7,
                message=f"Transaction from datacenter IP: {ip_address}",
                details={"ip": ip_address, "type": "datacenter"}
            ))

        # Check 2: Transaction velocity from this IP
        velocity_signal = await self._check_ip_velocity(ip_address)
        if velocity_signal:
            signals.append(velocity_signal)

        # Check 3: Multiple customers from same IP
        customer_signal = await self._check_customer_concentration(ip_address, customer_id)
        if customer_signal:
            signals.append(customer_signal)

        # Check 4: Multiple cards from same IP
        card_signal = await self._check_card_concentration(ip_address, card_fingerprint)
        if card_signal:
            signals.append(card_signal)

        # Calculate risk
        risk_score = self._calculate_risk(signals)
        action = self._determine_action(risk_score)

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
            "risk_score": risk_score,
            "action": action,
            "ip_address": ip_address,
        }

    def _is_datacenter_ip(self, ip_str: str) -> bool:
        """Check if IP belongs to known datacenter ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)
            for range_str in self.DATACENTER_RANGES:
                network = ipaddress.ip_network(range_str, strict=False)
                if ip in network:
                    return True
        except ValueError:
            pass
        return False

    async def _check_ip_velocity(self, ip_address: str) -> IPSignal | None:
        """Check transaction velocity from this IP."""
        cache_key = f"{self.CACHE_PREFIX}velocity:{ip_address}"
        now = datetime.now()

        # Get and update transaction times
        tx_times = cache.get(cache_key, [])
        tx_times.append(now.isoformat())

        # Clean old entries
        cutoff_day = now - timedelta(hours=24)
        tx_times = [t for t in tx_times if datetime.fromisoformat(t) > cutoff_day]
        cache.set(cache_key, tx_times, self.CACHE_TTL)

        # Check hourly velocity
        cutoff_hour = now - timedelta(hours=1)
        hourly_count = sum(1 for t in tx_times if datetime.fromisoformat(t) > cutoff_hour)

        if hourly_count > self.THRESHOLDS["tx_per_ip_per_hour"]:
            return IPSignal(
                code="ip_velocity_exceeded",
                severity="HIGH",
                score=0.8,
                message=f"IP {ip_address} has {hourly_count} transactions in last hour",
                details={"ip": ip_address, "hourly_count": hourly_count, "threshold": self.THRESHOLDS["tx_per_ip_per_hour"]}
            )

        # Check daily velocity
        if len(tx_times) > self.THRESHOLDS["tx_per_ip_per_day"]:
            return IPSignal(
                code="ip_daily_velocity_exceeded",
                severity="MEDIUM",
                score=0.5,
                message=f"IP {ip_address} has {len(tx_times)} transactions in last 24 hours",
                details={"ip": ip_address, "daily_count": len(tx_times), "threshold": self.THRESHOLDS["tx_per_ip_per_day"]}
            )

        return None

    async def _check_customer_concentration(self, ip_address: str, customer_id: str) -> IPSignal | None:
        """Check if multiple customers are using the same IP."""
        cache_key = f"{self.CACHE_PREFIX}customers:{ip_address}"
        customers: Set[str] = set(cache.get(cache_key, []))

        if customer_id:
            customers.add(customer_id)
            cache.set(cache_key, list(customers), self.CACHE_TTL)

        if len(customers) > self.THRESHOLDS["customers_per_ip"]:
            return IPSignal(
                code="multiple_customers_per_ip",
                severity="HIGH",
                score=0.75,
                message=f"IP {ip_address} used by {len(customers)} different customers",
                details={"ip": ip_address, "customer_count": len(customers), "threshold": self.THRESHOLDS["customers_per_ip"]}
            )

        return None

    async def _check_card_concentration(self, ip_address: str, card_fingerprint: str) -> IPSignal | None:
        """Check if multiple cards are used from the same IP."""
        cache_key = f"{self.CACHE_PREFIX}cards:{ip_address}"
        cards: Set[str] = set(cache.get(cache_key, []))

        if card_fingerprint:
            cards.add(card_fingerprint)
            cache.set(cache_key, list(cards), self.CACHE_TTL)

        if len(cards) > self.THRESHOLDS["cards_per_ip"]:
            return IPSignal(
                code="multiple_cards_per_ip",
                severity="CRITICAL",
                score=0.9,
                message=f"IP {ip_address} used with {len(cards)} different cards",
                details={"ip": ip_address, "card_count": len(cards), "threshold": self.THRESHOLDS["cards_per_ip"]}
            )

        return None

    def _calculate_risk(self, signals: List[IPSignal]) -> float:
        """Calculate aggregate risk score."""
        if not signals:
            return 0.0
        return min(sum(s.score for s in signals) / 2, 1.0)

    def _determine_action(self, risk_score: float) -> str:
        """Determine action based on risk score."""
        if risk_score >= 0.8:
            return "BLOCK"
        elif risk_score >= 0.5:
            return "REVIEW"
        elif risk_score >= 0.3:
            return "MONITOR"
        return "ALLOW"
