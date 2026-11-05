"""
Where FLIT is allowed to connect.

Every outbound request FLIT makes carries something a merchant or an end user
supplied — a visit id in a path, an email's domain, soon a merchant's webhook
URL. A fraud engine that can be pointed at its own cloud metadata endpoint,
or at the database next to it, is a fraud engine with a hole in the side.

Two rules, applied before any connection:

1. No private, loopback, link-local, carrier-NAT, multicast or reserved
   address, in any spelling. An IPv4 address hidden inside an IPv6 one
   (`::ffff:169.254.169.254`, `::ffff:a9fe:a9fe`) is the IPv4 address.
2. The address that was checked is the address that is dialled. DNS is
   resolved through a resolver that refuses blocked answers, and the socket
   connects to what that resolver returned — so a name that resolves to a
   public address for the check and a private one for the connection gains
   nothing.
"""

import ipaddress
from typing import Iterable, List
from urllib.parse import urlsplit

from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver


class BlockedAddressError(ValueError):
    """The request would reach an address FLIT must not talk to."""


# Ranges the standard library does not mark private but that are never a
# legitimate destination for FLIT.
_EXTRA_BLOCKED = (
    ipaddress.ip_network("100.64.0.0/10"),     # carrier-grade NAT; also cloud metadata on some providers
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),     # benchmarking
    ipaddress.ip_network("64:ff9b::/96"),      # NAT64 — carries an IPv4 address in the low bits
)


def _unwrap(address):
    """An IPv6 address carrying an IPv4 one is judged as the IPv4 one."""
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address.sixtofour is not None:
            return address.sixtofour
        if address.teredo is not None:
            return address.teredo[1]
        if address in _EXTRA_BLOCKED[3]:
            return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return address


def is_blocked_address(value, *, allow_loopback=False) -> bool:
    """
    Whether a literal IP address is one FLIT must not connect to.

    Anything that does not parse as an address is blocked too: a string
    this function cannot judge is not one to dial.
    """
    try:
        address = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return True

    address = _unwrap(address)

    if address.is_loopback:
        return not allow_loopback

    if (
        address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or getattr(address, "is_site_local", False)
    ):
        return True

    return any(address in network for network in _EXTRA_BLOCKED)


def check_url(url, *, allow_http=False, allow_loopback=False) -> str:
    """
    The host of a URL FLIT may connect to, or BlockedAddressError.

    Rejects anything but https (http only when asked), credentials in the
    URL, an empty host, and a host that is a blocked IP literal. A hostname
    passes here and is judged again, by address, when it resolves.
    """
    parts = urlsplit(str(url))

    schemes = ("https", "http") if allow_http else ("https",)
    if parts.scheme not in schemes:
        raise BlockedAddressError(f"scheme not allowed: {parts.scheme or 'none'}")

    if parts.username is not None or parts.password is not None:
        raise BlockedAddressError("credentials in URL")

    host = parts.hostname
    if not host:
        raise BlockedAddressError("no host")

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return host  # a name; judged on resolution

    if is_blocked_address(host, allow_loopback=allow_loopback):
        raise BlockedAddressError(f"blocked address: {host}")

    return host


class GuardedResolver(AbstractResolver):
    """
    A DNS resolver that refuses blocked answers.

    aiohttp connects to the addresses its resolver returns, so refusing them
    here is what pins the connection to a checked address. If *any* answer
    for a name is blocked the whole name is refused: a name that is partly
    private is a name somebody is playing games with.
    """

    def __init__(self, inner: AbstractResolver = None, *, allow_loopback=False):
        self._inner = inner or DefaultResolver()
        self._allow_loopback = allow_loopback

    async def resolve(self, host: str, port: int = 0, family: int = 0) -> List[dict]:
        answers = await self._inner.resolve(host, port, family)
        self.guard(host, (answer["host"] for answer in answers))
        return answers

    def guard(self, host: str, addresses: Iterable[str]):
        addresses = list(addresses)

        if not addresses:
            raise BlockedAddressError(f"{host} resolved to nothing")

        blocked = [
            address for address in addresses
            if is_blocked_address(address, allow_loopback=self._allow_loopback)
        ]

        if blocked:
            raise BlockedAddressError(f"{host} resolves to a blocked address: {blocked[0]}")

    async def close(self) -> None:
        await self._inner.close()
