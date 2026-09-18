import bisect
import logging
import ipaddress
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from dataclasses import dataclass, field
from uuid import uuid4

import requests
from django.core.cache import cache

from kernel.config import Config


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


class IPRangeSet:
    """IPs and CIDR ranges merged into sorted disjoint intervals for bisect lookup."""

    def __init__(self, entries: Iterable[str]):
        intervals = []
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry.strip(), strict=False)
            except ValueError:
                continue
            intervals.append((
                network.version,
                int(network.network_address),
                int(network.broadcast_address),
            ))
        intervals.sort()

        merged: List[Tuple[int, int, int]] = []
        for version, start, end in intervals:
            if merged and merged[-1][0] == version and start <= merged[-1][2] + 1:
                last = merged[-1]
                merged[-1] = (version, last[1], max(last[2], end))
            else:
                merged.append((version, start, end))

        self.intervals = merged
        self.starts = [(version, start) for version, start, _ in merged]

    def __len__(self):
        return len(self.intervals)

    def __contains__(self, ip_address: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        index = bisect.bisect_right(self.starts, (ip.version, int(ip))) - 1
        if index < 0:
            return False

        version, start, end = self.intervals[index]
        return version == ip.version and start <= int(ip) <= end


class SharedIPList:
    """
    An IP/CIDR list stored in the Django cache (Redis in production) so every
    worker sees the same data, with a per-process parsed copy that is only
    reloaded when the list's version stamp changes.
    """

    TIMEOUT_SECONDS = 7 * 24 * 3600

    def __init__(self, name: str):
        self.data_key = f"ip_intel:{name}:entries"
        self.version_key = f"ip_intel:{name}:version"
        self._version = None
        self._ranges = IPRangeSet([])

    def store(self, entries: List[str]) -> None:
        version = uuid4().hex
        cache.set(self.data_key, entries, timeout=self.TIMEOUT_SECONDS)
        cache.set(self.version_key, version, timeout=self.TIMEOUT_SECONDS)

    def current(self) -> IPRangeSet:
        version = cache.get(self.version_key)
        if version != self._version:
            self._ranges = IPRangeSet(cache.get(self.data_key) or [])
            self._version = version
        return self._ranges

    def __contains__(self, ip_address: str) -> bool:
        return ip_address in self.current()


class GeoIPDatabase:
    """Lazy MaxMind GeoLite2 readers; lookups are local, no network calls."""

    ASN_FILE = "GeoLite2-ASN.mmdb"
    COUNTRY_FILE = "GeoLite2-Country.mmdb"

    _readers = None
    _warned = False

    @classmethod
    def readers(cls):
        if cls._readers is None:
            cls._readers = cls._open_readers()
        return cls._readers

    @classmethod
    def _open_readers(cls):
        db_path = Config.geoip_db_path
        if not db_path:
            cls._warn("GEOIP_DB_PATH is not set; IP geolocation is disabled")
            return {}

        try:
            import geoip2.database
        except ImportError:
            cls._warn("geoip2 is not installed; IP geolocation is disabled")
            return {}

        readers = {}
        for name, filename in (("asn", cls.ASN_FILE), ("country", cls.COUNTRY_FILE)):
            path = Path(db_path) / filename
            if path.exists():
                readers[name] = geoip2.database.Reader(str(path))
            else:
                cls._warn(f"GeoIP database not found: {path}")
        return readers

    @classmethod
    def _warn(cls, message):
        if not cls._warned:
            logger.warning(message)
            cls._warned = True

    @classmethod
    def lookup(cls, ip_address: str) -> Optional[Dict[str, Any]]:
        readers = cls.readers()
        if not readers:
            return None

        data = {}

        if "asn" in readers:
            try:
                response = readers["asn"].asn(ip_address)
                if response.autonomous_system_number:
                    data["asn"] = f"AS{response.autonomous_system_number}"
                data["asn_org"] = response.autonomous_system_organization
                data["isp"] = response.autonomous_system_organization
            except Exception:
                pass

        if "country" in readers:
            try:
                response = readers["country"].country(ip_address)
                data["country_code"] = response.country.iso_code
            except Exception:
                pass

        return data or None


class IPIntelligence:
    CACHE_TTL_SECONDS = 3600
    REQUEST_TIMEOUT_SECONDS = 30

    TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

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

    # Coarse cloud ranges, used only when no GeoIP ASN data is available.
    FALLBACK_DATACENTER_RANGES = IPRangeSet([
        "52.0.0.0/11",      # AWS US East
        "54.0.0.0/8",       # AWS Global
        "99.80.0.0/12",     # AWS EU
        "35.0.0.0/8",       # GCP
        "104.196.0.0/14",   # GCP
        "13.0.0.0/8",       # Azure
        "20.0.0.0/8",       # Azure
        "40.0.0.0/8",       # Azure
    ])

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

    TOR_EXIT_NODES = SharedIPList("tor_exit_nodes")
    THREAT_LIST = SharedIPList("threat_list")

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

        if not info.asn and ip_address in cls.FALLBACK_DATACENTER_RANGES:
            info.is_datacenter = True
            info.risk_score += 0.3
            risk_factors.append("datacenter_ip")

        info.is_known_attacker = await cls._check_threat_lists(ip_address)
        if info.is_known_attacker:
            info.risk_score += 0.9
            risk_factors.append("known_attacker")

        info.risk_score = min(info.risk_score, 1.0)
        info.risk_factors = risk_factors

        return info

    @classmethod
    def _is_private_ip(cls, ip_address: str) -> bool:
        try:
            return not ipaddress.ip_address(ip_address).is_global
        except ValueError:
            return True

    @classmethod
    async def _get_geo_data(cls, ip_address: str) -> Optional[Dict[str, Any]]:
        return GeoIPDatabase.lookup(ip_address)

    @classmethod
    async def _check_threat_lists(cls, ip_address: str) -> bool:
        return ip_address in cls.THREAT_LIST

    @classmethod
    def refresh_tor_exit_nodes(cls) -> int:
        entries = cls._download_list(cls.TOR_EXIT_LIST_URL)
        cls.TOR_EXIT_NODES.store(entries)
        logger.info(f"Loaded {len(entries)} Tor exit nodes")
        return len(entries)

    @classmethod
    def refresh_threat_list(cls, url: Optional[str] = None) -> int:
        entries = cls._download_list(url or Config.threat_list_url)
        cls.THREAT_LIST.store(entries)
        logger.info(f"Loaded {len(entries)} threat list entries")
        return len(entries)

    @classmethod
    def _download_list(cls, url: str) -> List[str]:
        response = requests.get(url, timeout=cls.REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        return [
            line.strip()
            for line in response.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]

    @classmethod
    def is_suspicious(cls, info: IPRiskInfo, threshold: float = 0.5) -> bool:
        return (
            info.risk_score >= threshold
            or info.is_tor
            or info.is_known_attacker
            or (info.is_vpn and info.is_datacenter)
        )
