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
