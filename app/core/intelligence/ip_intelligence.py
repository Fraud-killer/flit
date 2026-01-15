import re
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from django.core.cache import cache


logger = logging.getLogger(__name__)


@dataclass
class IPRiskInfo:
    ip_address: str
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_bot: bool = False
    is_known_attacker: bool = False
    risk_score: float = 0.0
    country_code: Optional[str] = None
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "is_tor": self.is_tor,
            "is_datacenter": self.is_datacenter,
            "is_bot": self.is_bot,
            "is_known_attacker": self.is_known_attacker,
            "risk_score": self.risk_score,
            "country_code": self.country_code,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "isp": self.isp,
            "risk_factors": self.risk_factors,
        }


class IPIntelligence:
    CACHE_TTL_SECONDS = 3600
    
    KNOWN_DATACENTER_ASNS = {
        "AS14061",  # DigitalOcean
        "AS16509",  # Amazon AWS
        "AS15169",  # Google Cloud
        "AS8075",   # Microsoft Azure
        "AS13335",  # Cloudflare
        "AS14618",  # Amazon
        "AS16276",  # OVH
        "AS24940",  # Hetzner
        "AS63949",  # Linode
        "AS20473",  # Vultr
        "AS46606",  # Unified Layer
        "AS36352",  # ColoCrossing
    }

    DATACENTER_ISP_KEYWORDS = [
        "amazon", "aws", "google", "microsoft", "azure", "digitalocean",
        "linode", "vultr", "ovh", "hetzner", "cloudflare", "oracle cloud",
        "alibaba", "tencent", "hosting", "datacenter", "data center",
        "server", "vps", "cloud", "colocation",
    ]

    VPN_ISP_KEYWORDS = [
        "vpn", "private internet", "nordvpn", "expressvpn", "surfshark",
        "cyberghost", "protonvpn", "mullvad", "ipvanish", "tunnelbear",
        "hotspot shield", "windscribe", "hide.me", "purevpn",
    ]

    HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU", "RU", "BY"}

    TOR_EXIT_NODES: Set[str] = set()

    @classmethod
    def get_cache_key(cls, ip_address: str) -> str:
        return f"ip_intel:{ip_address}"

    @classmethod
    async def analyze(cls, ip_address: str) -> IPRiskInfo:
        cache_key = cls.get_cache_key(ip_address)
        cached = cache.get(cache_key)
        if cached:
            return IPRiskInfo(**cached)

        info = await cls._perform_analysis(ip_address)

        cache.set(cache_key, info.to_dict(), timeout=cls.CACHE_TTL_SECONDS)

        return info

    @classmethod
    def analyze_sync(cls, ip_address: str) -> IPRiskInfo:
        from asgiref.sync import async_to_sync
        return async_to_sync(cls.analyze)(ip_address)

    @classmethod
    async def _perform_analysis(cls, ip_address: str) -> IPRiskInfo:
        info = IPRiskInfo(ip_address=ip_address)
        risk_factors = []

        if cls._is_private_ip(ip_address):
            return info

        if ip_address in cls.TOR_EXIT_NODES:
            info.is_tor = True
            info.risk_score += 0.8
            risk_factors.append("tor_exit_node")

        geo_data = await cls._get_geo_data(ip_address)
        if geo_data:
            info.country_code = geo_data.get("country_code")
            info.asn = geo_data.get("asn")
            info.asn_org = geo_data.get("asn_org")
            info.isp = geo_data.get("isp")

            if info.country_code in cls.HIGH_RISK_COUNTRIES:
                info.risk_score += 0.5
                risk_factors.append(f"high_risk_country:{info.country_code}")

            if info.asn in cls.KNOWN_DATACENTER_ASNS:
                info.is_datacenter = True
                info.risk_score += 0.3
                risk_factors.append("datacenter_ip")

            if info.isp:
                isp_lower = info.isp.lower()

                for keyword in cls.DATACENTER_ISP_KEYWORDS:
                    if keyword in isp_lower:
                        info.is_datacenter = True
                        if "datacenter_ip" not in risk_factors:
                            info.risk_score += 0.3
                            risk_factors.append("datacenter_ip")
                        break

                for keyword in cls.VPN_ISP_KEYWORDS:
                    if keyword in isp_lower:
                        info.is_vpn = True
                        info.risk_score += 0.4
                        risk_factors.append("vpn_detected")
                        break

        info.is_known_attacker = await cls._check_threat_lists(ip_address)
        if info.is_known_attacker:
            info.risk_score += 0.9
            risk_factors.append("known_attacker")

        info.risk_score = min(info.risk_score, 1.0)
        info.risk_factors = risk_factors

        return info

    @classmethod
    def _is_private_ip(cls, ip_address: str) -> bool:
        private_patterns = [
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^192\.168\.",
            r"^127\.",
            r"^169\.254\.",
            r"^::1$",
            r"^fc00:",
            r"^fe80:",
        ]
        return any(re.match(pattern, ip_address) for pattern in private_patterns)

    @classmethod
    async def _get_geo_data(cls, ip_address: str) -> Optional[Dict[str, Any]]:
        return None

    @classmethod
    async def _check_threat_lists(cls, ip_address: str) -> bool:
        return False

    @classmethod
    async def refresh_tor_exit_nodes(cls) -> None:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://check.torproject.org/torbulkexitlist",
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        cls.TOR_EXIT_NODES = set(
                            line.strip()
                            for line in text.split("\n")
                            if line.strip() and not line.startswith("#")
                        )
                        logger.info(f"Loaded {len(cls.TOR_EXIT_NODES)} Tor exit nodes")
        except Exception as e:
            logger.error(f"Failed to refresh Tor exit nodes: {e}")

    @classmethod
    def is_suspicious(cls, info: IPRiskInfo, threshold: float = 0.5) -> bool:
        return (
            info.risk_score >= threshold
            or info.is_tor
            or info.is_known_attacker
            or (info.is_vpn and info.is_datacenter)
        )
