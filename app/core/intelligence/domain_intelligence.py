"""
Domain intelligence: can this address actually receive mail, and how long has
its domain existed?

Two questions the local email heuristics cannot answer. A throwaway provider
that is not on any list still has to publish MX records, and a domain
registered yesterday to run a signup flood still has a registration date.
Both are cheap to check and expensive to fake.

Answered over DNS-over-HTTPS and RDAP, both plain HTTPS, so this adds no new
dependency to a deployment that already speaks HTTP. Both are best-effort:
every failure returns "unknown", and a rule that knows nothing says nothing.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone as datetime_timezone
from typing import List, Optional

import aiohttp
from django.core.cache import cache

from kernel.config import Config


logger = logging.getLogger(__name__)


DOH_URL = "https://cloudflare-dns.com/dns-query"
RDAP_URL = "https://rdap.org/domain/{domain}"

LOOKUP_TIMEOUT_SECONDS = 4

MX_CACHE_SECONDS = 24 * 60 * 60
RDAP_CACHE_SECONDS = 7 * 24 * 60 * 60

# A domain younger than this is worth a second look. Long enough that an
# ordinary new business is past it before it matters, short enough to catch a
# domain registered for one campaign.
NEW_DOMAIN_DAYS = 30

# The providers most real users are on. Checked first and never looked up:
# it saves the request, and it means an outage in DNS or RDAP cannot affect
# the overwhelming majority of honest signups.
ESTABLISHED_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com", "aol.com", "protonmail.com",
    "proton.me", "gmx.com", "gmx.de", "zoho.com", "fastmail.com",
    "yandex.com", "yandex.ru", "mail.com", "hey.com", "qq.com", "163.com",
    "126.com", "naver.com", "daum.net", "orange.fr", "web.de", "t-online.de",
    "libero.it", "free.fr", "sfr.fr", "bluewin.ch", "rediffmail.com",
}


@dataclass
class DomainInfo:
    domain: str
    checked: bool = False
    has_mx: Optional[bool] = None
    mx_hosts: List[str] = field(default_factory=list)
    registered_at: Optional[datetime] = None
    age_days: Optional[int] = None
    established: bool = False

    @property
    def is_newly_registered(self) -> bool:
        return self.age_days is not None and self.age_days < NEW_DOMAIN_DAYS

    @property
    def cannot_receive_mail(self) -> bool:
        # Only a definite "no MX" counts. Unknown is not evidence.
        return self.has_mx is False

    def as_context(self):
        return dict(
            domain=self.domain,
            has_mx=self.has_mx,
            age_days=self.age_days,
            registered_at=self.registered_at.isoformat() if self.registered_at else None,
        )


async def _get_json(url, *, params=None, headers=None):
    timeout = aiohttp.ClientTimeout(total=LOOKUP_TIMEOUT_SECONDS)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, params=params, headers=headers) as reply:
            if reply.status != 200:
                return None
            return await reply.json(content_type=None)


async def _mx_records(domain):
    """MX hosts for a domain over DNS-over-HTTPS, or None if unknown."""
    body = await _get_json(
        DOH_URL,
        params={"name": domain, "type": "MX"},
        headers={"Accept": "application/dns-json"},
    )

    if body is None:
        return None

    # NXDOMAIN. The domain does not exist at all, which is a definite no.
    if body.get("Status") == 3:
        return []

    if body.get("Status") != 0:
        return None

    return [
        answer.get("data", "").split()[-1].rstrip(".")
        for answer in body.get("Answer", [])
        if answer.get("type") == 15 and answer.get("data")
    ]


async def _registration_date(domain):
    """When a domain was registered, over RDAP, or None if unknown."""
    body = await _get_json(RDAP_URL.format(domain=domain))

    if not body:
        return None

    for event in body.get("events", []):
        if event.get("eventAction") != "registration":
            continue

        stamp = event.get("eventDate")
        if not stamp:
            continue

        try:
            return datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            return None

    return None


class DomainIntelligence:
    @classmethod
    def enabled(cls):
        """
        Whether outbound lookups are permitted.

        Read through a method rather than the setting directly so a caller —
        a test, a replay, a deployment with no egress — can turn it off
        without the config being mutable.
        """
        return bool(Config.domain_lookups_enabled)

    @classmethod
    async def analyze(cls, domain):
        """
        Everything known about a domain, best effort.

        Never raises, never blocks a decision for long, and returns a result
        whose fields are all None when nothing could be established — so a
        network outage reads as "no finding", not as "clean" or "suspicious".
        """
        info = DomainInfo(domain=(domain or "").strip().lower())

        if not info.domain:
            return info

        if info.domain in ESTABLISHED_PROVIDERS:
            info.established = True
            info.has_mx = True
            return info

        if not cls.enabled():
            return info

        cache_key = f"flit:domain:{info.domain}"

        try:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
        except Exception:
            logger.debug("Domain cache unavailable", exc_info=True)

        info.checked = True

        try:
            hosts = await _mx_records(info.domain)
            if hosts is not None:
                info.mx_hosts = hosts
                info.has_mx = bool(hosts)
        except Exception:
            logger.debug(f"MX lookup failed for {info.domain}", exc_info=True)

        try:
            registered_at = await _registration_date(info.domain)
            if registered_at:
                info.registered_at = registered_at
                info.age_days = (
                    datetime.now(datetime_timezone.utc) - registered_at
                ).days
        except Exception:
            logger.debug(f"RDAP lookup failed for {info.domain}", exc_info=True)

        try:
            cache.set(
                cache_key, info,
                RDAP_CACHE_SECONDS if info.registered_at else MX_CACHE_SECONDS,
            )
        except Exception:
            logger.debug("Could not cache domain intelligence", exc_info=True)

        return info
