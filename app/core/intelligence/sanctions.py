"""
OFAC sanctions screening for wallet addresses.

This is not a compliance product. Chainalysis, TRM and Elliptic sell sanctions
screening properly — with attribution, indirect exposure, cluster ownership
and the audit trail an examiner expects — and a fintech with real obligations
should buy one.

What this is: the cheap, exact half. OFAC publishes the digital currency
addresses on its SDN list publicly and for free. Checking an address against
that list costs one string comparison, and *not* checking it is very hard to
defend. So FLIT does the part that is free and says plainly that it is not
the whole of the obligation.

The line is the same one the rest of FLIT draws: a list lookup is not chain
analytics. No tracing, no clustering, no indirect exposure — a sanctioned
address one hop away from this one is exactly the case this will miss, and
exactly what the vendors are for.

Matching is chain-agnostic on the normalised address. OFAC tags entries by
asset (XBT, ETH, USDT, TRX and so on) rather than by the chain a transfer
happens to use, and an address string is long enough that a collision across
chains is not a practical concern. Matching on the string rather than on our
guess at the chain avoids missing a hit because the labels disagreed.
"""

import logging
import re
from uuid import uuid4

import requests
from django.core.cache import cache
from django.utils import timezone

from kernel.config import Config

from .wallet_intelligence import is_evm_address, normalize_address


logger = logging.getLogger(__name__)


REQUEST_TIMEOUT_SECONDS = 30
CACHE_TIMEOUT_SECONDS = 30 * 24 * 3600

# A list older than this should not be trusted to be current. OFAC updates the
# SDN list on no fixed schedule, often several times a month.
STALE_AFTER_DAYS = 7

# Digital currency entries in the SDN XML look like:
#   <id><idType>Digital Currency Address - ETH</idType>
#       <idNumber>0x...</idNumber></id>
# Parsed with a targeted expression rather than a full XML parse: the shape is
# stable, and it avoids handing a 40MB third-party document to an XML parser
# for the sake of two fields.
ENTRY_PATTERN = re.compile(
    r"Digital Currency Address\s*-\s*(?P<asset>[A-Z0-9]+)\s*</idType>\s*"
    r"<idNumber>(?P<address>[^<]+)</idNumber>",
    re.IGNORECASE,
)


def screening_key(address):
    """
    The form an address is compared in: EVM lowercased, everything else left
    alone, because only EVM addresses are case-insensitive.
    """
    if not address or not isinstance(address, str):
        return None

    candidate = address.strip()

    if not candidate:
        return None

    if is_evm_address(candidate):
        return candidate.lower()

    normalized = normalize_address(candidate)
    return normalized or candidate


class SanctionsList:
    """
    The OFAC digital currency addresses, in the shared cache so every worker
    screens against the same data, with a per-process copy reloaded only when
    the version stamp changes.
    """

    DATA_KEY = "sanctions:ofac:addresses"
    META_KEY = "sanctions:ofac:meta"
    VERSION_KEY = "sanctions:ofac:version"

    _version = None
    _addresses = frozenset()

    @classmethod
    def store(cls, addresses, source=None):
        version = uuid4().hex
        cache.set(cls.DATA_KEY, sorted(addresses), timeout=CACHE_TIMEOUT_SECONDS)
        cache.set(cls.VERSION_KEY, version, timeout=CACHE_TIMEOUT_SECONDS)
        cache.set(
            cls.META_KEY,
            dict(loaded_at=timezone.now().isoformat(), count=len(addresses),
                 source=source or Config.sanctions_list_url),
            timeout=CACHE_TIMEOUT_SECONDS,
        )

    @classmethod
    def current(cls):
        try:
            version = cache.get(cls.VERSION_KEY)
        except Exception:
            logger.warning("Sanctions cache unavailable", exc_info=True)
            return frozenset()

        if version != cls._version:
            cls._addresses = frozenset(cache.get(cls.DATA_KEY) or [])
            cls._version = version

        return cls._addresses

    @classmethod
    def status(cls):
        """
        What is loaded and how old it is.

        `loaded` being false is the state that matters: it means screening is
        not happening, which must never pass silently.
        """
        meta = {}
        try:
            meta = cache.get(cls.META_KEY) or {}
        except Exception:
            logger.warning("Sanctions metadata unavailable", exc_info=True)

        addresses = cls.current()
        loaded_at = meta.get("loaded_at")
        age_days = None

        if loaded_at:
            try:
                age_days = (
                    timezone.now() - timezone.datetime.fromisoformat(loaded_at)
                ).days
            except (ValueError, TypeError):
                age_days = None

        return dict(
            loaded=bool(addresses),
            count=len(addresses),
            loaded_at=loaded_at,
            age_days=age_days,
            stale=age_days is not None and age_days > STALE_AFTER_DAYS,
            source=meta.get("source"),
        )

    @classmethod
    def contains(cls, address):
        key = screening_key(address)
        return bool(key) and key in cls.current()

    @classmethod
    def parse(cls, document):
        """Digital currency addresses in an OFAC SDN document."""
        addresses = set()

        for match in ENTRY_PATTERN.finditer(document or ""):
            key = screening_key(match.group("address"))
            if key:
                addresses.add(key)

        return addresses

    @classmethod
    def refresh(cls, url=None):
        """
        Download and store the list. Raises on failure: a refresh that fails
        quietly is how a list silently goes stale.
        """
        source = url or Config.sanctions_list_url
        response = requests.get(source, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()

        addresses = cls.parse(response.text)

        if not addresses:
            raise ValueError(
                f"No digital currency addresses found at {source}; "
                "refusing to overwrite the loaded list with nothing"
            )

        cls.store(addresses, source=source)
        logger.info(f"Loaded {len(addresses)} sanctioned addresses from {source}")
        return len(addresses)
