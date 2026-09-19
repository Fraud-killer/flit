"""
Wallet address intelligence.

FLIT does not read chains. Chainalysis, TRM and Elliptic already do that well
and every crypto fintech of any size pays one of them. What those tools do
badly is the half that happens before anything is signed: the device, the
session, the signup, the takeover. That is FLIT's half, and a wallet address
is the identifier that ties it together.

So this module does exactly one thing — turn an address into a stable,
comparable key — and deliberately nothing else. No balances, no clustering,
no sanctions screening, no provenance. Those are somebody else's product.

The distinction that matters here is whose address it is:

  own address          the user controls it, so it identifies them
  counterparty address they sent to it, so it does not

Treating a withdrawal destination as identity would merge every customer who
ever paid the same exchange, which is the same mistake as counting accounts
on a carrier-grade NAT address.
"""

import re


# EVM addresses are case-insensitive: the mixed case is a checksum, not part
# of the address. Everything else here is case-sensitive, and lowercasing a
# Bitcoin or Solana address would break it.
EVM_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")

EVM_CHAINS = {
    "ethereum", "eth", "polygon", "matic", "base", "arbitrum", "optimism",
    "bsc", "binance-smart-chain", "avalanche", "avax", "linea", "scroll",
    "zksync", "celo", "gnosis", "fantom", "blast", "mantle",
}

# Chains whose addresses are case-sensitive; kept for documentation and for
# the validity check, not for normalisation.
CASE_SENSITIVE_CHAINS = {
    "bitcoin", "btc", "solana", "sol", "tron", "trx", "stellar", "xlm",
    "ripple", "xrp", "cardano", "ada", "cosmos", "atom", "near", "aptos",
    "sui", "litecoin", "ltc",
}


def is_evm_address(address):
    return bool(address) and bool(EVM_PATTERN.match(address.strip()))


def normalize_address(address, chain=None):
    """
    The canonical form of an address, or None if it is not usable as a key.

    EVM addresses are lowercased so that a checksummed address and its
    lowercase form resolve to one key — otherwise the same wallet appears as
    two identities depending on how the merchant happened to send it.
    """
    if not address or not isinstance(address, str):
        return None

    candidate = address.strip()

    if not candidate or len(candidate) < 16 or len(candidate) > 128:
        return None

    if " " in candidate:
        return None

    if is_evm_address(candidate):
        return candidate.lower()

    # An EVM-looking address on a non-EVM chain, or vice versa, is a mapping
    # error worth refusing rather than silently keying on.
    if chain and chain.strip().lower() in EVM_CHAINS and not is_evm_address(candidate):
        return None

    return candidate


def address_key(address, chain=None):
    """
    The correlation key for an address.

    Namespaced by chain family rather than by chain, because the same EVM
    address is the same wallet on every EVM chain — a ring that collects on
    Polygon and withdraws on Base is one actor, and keying per chain would
    hide that. Non-EVM addresses are unique to their chain already.
    """
    normalized = normalize_address(address, chain)

    if normalized is None:
        return None

    if is_evm_address(normalized):
        return f"evm:{normalized}"

    family = (chain or "unknown").strip().lower()
    return f"{family}:{normalized}"


def redact(address):
    """A form safe to show an analyst: 0x1234…cdef."""
    normalized = (address or "").strip()

    if len(normalized) < 12:
        return ""

    return f"{normalized[:6]}…{normalized[-4:]}"


# --------------------------------------------------------------------------
# On-chain history
#
# One question, asked of a public node: has this address ever done anything?
#
# That is deliberately the whole of it. Tracing, clustering, balances and
# provenance are chain analytics — Chainalysis, TRM and Elliptic do that
# properly and every crypto fintech of any size already pays one. But "is
# this wallet brand new" needs no vendor, no key and no graph: it is a single
# JSON-RPC call, and it is the same signal as a domain registered yesterday.
# Real users arrive with history. Farms arrive fresh.
# --------------------------------------------------------------------------

import logging
from dataclasses import dataclass
from typing import Optional

import aiohttp
from django.core.cache import cache

from kernel.config import Config


logger = logging.getLogger(__name__)


# Public endpoints, so this works with no configuration. A deployment that
# cares about rate limits or privacy sets CHAIN_RPC_URLS to its own nodes.
DEFAULT_RPC_URLS = {
    "ethereum": "https://eth.llamarpc.com",
    "eth": "https://eth.llamarpc.com",
    "polygon": "https://polygon-rpc.com",
    "matic": "https://polygon-rpc.com",
    "base": "https://mainnet.base.org",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "optimism": "https://mainnet.optimism.io",
    "bnb": "https://bsc-dataseed.binance.org",
    "bsc": "https://bsc-dataseed.binance.org",
}

RPC_TIMEOUT_SECONDS = 4

# An address that has history will always have history, so that answer can be
# cached for a long time. "No history yet" can change with the next block, so
# it is cached briefly.
HAS_HISTORY_CACHE_SECONDS = 30 * 24 * 60 * 60
NO_HISTORY_CACHE_SECONDS = 10 * 60


@dataclass
class WalletHistory:
    address_key: str
    checked: bool = False
    # None means unknown — the lookup did not answer. Never read as clean.
    transaction_count: Optional[int] = None
    is_contract: Optional[bool] = None

    @property
    def is_fresh(self) -> bool:
        """The address has never sent a transaction."""
        return self.transaction_count == 0

    @property
    def has_history(self) -> bool:
        return bool(self.transaction_count)

    def as_context(self):
        return dict(
            transaction_count=self.transaction_count,
            is_contract=self.is_contract,
        )


def rpc_url_for(chain):
    urls = {**DEFAULT_RPC_URLS, **(Config.chain_rpc_urls or {})}
    return urls.get((chain or "").strip().lower())


async def _rpc(url, method, params):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    timeout = aiohttp.ClientTimeout(total=RPC_TIMEOUT_SECONDS)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(url, json=payload) as reply:
            if reply.status != 200:
                return None
            body = await reply.json(content_type=None)

    if not isinstance(body, dict) or body.get("error"):
        return None

    return body.get("result")


class WalletChainIntelligence:
    @classmethod
    def enabled(cls):
        """
        Whether outbound RPC calls are permitted. Read through a method so a
        test or an air-gapped deployment can turn it off without the config
        being mutable.
        """
        return bool(Config.chain_lookups_enabled)

    @classmethod
    async def analyze(cls, address, chain):
        """
        Whether an address has any on-chain history, best effort.

        Never raises and never blocks a decision for long. Every field is
        None when nothing could be established, so an unreachable node reads
        as "unknown" rather than as clean or as suspicious.
        """
        key = address_key(address, chain)
        history = WalletHistory(address_key=key or "")

        if not key or not is_evm_address(normalize_address(address, chain) or ""):
            # Only EVM is supported today. A Tron or Solana address returns
            # unknown rather than a wrong answer.
            return history

        if not cls.enabled():
            return history

        url = rpc_url_for(chain)
        if not url:
            return history

        cache_key = f"flit:wallet_history:{key}"

        try:
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
        except Exception:
            logger.debug("Wallet history cache unavailable", exc_info=True)

        history.checked = True
        normalized = normalize_address(address, chain)

        try:
            count = await _rpc(url, "eth_getTransactionCount", [normalized, "latest"])
            if isinstance(count, str):
                history.transaction_count = int(count, 16)
        except Exception:
            logger.debug(f"Nonce lookup failed for {key}", exc_info=True)

        try:
            code = await _rpc(url, "eth_getCode", [normalized, "latest"])
            if isinstance(code, str):
                history.is_contract = code not in ("0x", "0x0")
        except Exception:
            logger.debug(f"Code lookup failed for {key}", exc_info=True)

        try:
            if history.transaction_count is not None:
                cache.set(
                    cache_key, history,
                    HAS_HISTORY_CACHE_SECONDS if history.has_history
                    else NO_HISTORY_CACHE_SECONDS,
                )
        except Exception:
            logger.debug("Could not cache wallet history", exc_info=True)

        return history
