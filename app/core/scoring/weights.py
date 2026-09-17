from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class RiskWeights:
    device_expired: float = 0.3
    new_device_country: float = 0.4
    unregistered_device: float = 0.5
    aml_cft_limit_exceeded: float = 0.9
    maximum_single_debit_exceeded: float = 0.7
    maximum_single_credit_exceeded: float = 0.6
    maximum_cumulative_balance_exceeded: float = 0.8
    maximum_daily_cumulative_debit_exceeded: float = 0.7
    velocity_exceeded: float = 0.6
    impossible_travel: float = 0.85
    account_takeover: float = 0.95
    multiple_devices: float = 0.5
    multiple_ips: float = 0.4
    high_failure_rate: float = 0.6
    tor_exit_node: float = 0.8
    known_attacker: float = 0.9
    proxy_detected: float = 0.5
    vpn_detected: float = 0.4
    datacenter_ip: float = 0.3
    high_risk_country: float = 0.5
    bot_detected: float = 0.7

    category_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "transaction": 1.0,
        "authentication": 0.8,
        "device": 0.7,
        "account": 0.9,
    })

    time_decay_hours: float = 24.0
    recency_boost: float = 1.2

    def get_weight(self, rule_code: str, default: Optional[float] = None) -> float:
        """
        Weight for a rule code. Codes without a configured weight fall back to
        `default` (the score a rule attached to its message), then to 0.5.
        """
        if rule_code.startswith("bot_detected:"):
            return self.bot_detected

        weight_map = {
            "device_expired": self.device_expired,
            "new_device_country": self.new_device_country,
            "unregistered_device": self.unregistered_device,
            "aml_cft_limit_exceeded": self.aml_cft_limit_exceeded,
            "maximum_single_debit_exceeded": self.maximum_single_debit_exceeded,
            "maximum_single_credit_exceeded": self.maximum_single_credit_exceeded,
            "maximum_cumulative_balance_exceeded": self.maximum_cumulative_balance_exceeded,
            "maximum_daily_cumulative_debit_exceeded": self.maximum_daily_cumulative_debit_exceeded,
            "velocity_exceeded_per_minute": self.velocity_exceeded,
            "velocity_exceeded_per_5_minutes": self.velocity_exceeded,
            "velocity_exceeded_per_hour": self.velocity_exceeded,
            "velocity_exceeded_per_day": self.velocity_exceeded,
            "impossible_travel_detected": self.impossible_travel,
            "account_takeover_risk": self.account_takeover,
            "multiple_devices_detected": self.multiple_devices,
            "multiple_ips_detected": self.multiple_ips,
            "high_failure_rate": self.high_failure_rate,
            "tor_exit_node": self.tor_exit_node,
            "known_attacker": self.known_attacker,
            "proxy_detected": self.proxy_detected,
            "vpn_detected": self.vpn_detected,
            "datacenter_ip": self.datacenter_ip,
            "high_risk_country": self.high_risk_country,
        }
        if rule_code in weight_map:
            return weight_map[rule_code]
        return 0.5 if default is None else default


DEFAULT_WEIGHTS = RiskWeights()
