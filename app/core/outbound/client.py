"""
The one way FLIT makes an HTTP request to somewhere it does not control.

Every call goes through the SSRF guard (core.outbound.ssrf), never follows a
redirect it has not judged, caps what it will read, and times out. Callers
get a parsed JSON body or None; the reasons are logged, not raised, because
a lookup that failed is a lookup that failed — the rule reading it decides
what that means.
"""

import json
import logging
from typing import Any, Optional
from urllib.parse import urljoin

import aiohttp

from .ssrf import BlockedAddressError, GuardedResolver, check_url


logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT_SECONDS = 5
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class OutboundError(Exception):
    pass


async def send(
    url: str,
    *,
    method: str = "POST",
    body: bytes = b"",
    headers: Optional[dict] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = 64 * 1024,
    allow_http: bool = False,
    allow_loopback: bool = False,
):
    """
    One request to a URL somebody else controls — a merchant's webhook, a
    decision hook. Returns (status, body_bytes) or raises OutboundError.
    Never follows a redirect: a webhook that redirects is a webhook that
    changed, and the merchant can change it in the console.
    """
    check_url(url, allow_http=allow_http, allow_loopback=allow_loopback)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    try:
        async with aiohttp.ClientSession(
            timeout=client_timeout, connector=_connector(allow_loopback),
        ) as session:
            async with session.request(
                method, url, data=body, headers=headers or {}, allow_redirects=False,
            ) as reply:
                raw = await reply.content.read(max_bytes + 1)
                return reply.status, raw[:max_bytes]
    except BlockedAddressError:
        raise
    except (aiohttp.ClientError, TimeoutError, OSError) as error:
        raise OutboundError(repr(error)) from error




def _connector(allow_loopback):
    return aiohttp.TCPConnector(resolver=GuardedResolver(allow_loopback=allow_loopback))


async def fetch_json(
    url: str,
    *,
    method: str = "GET",
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    json_body: Any = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = 0,
    allow_http: bool = False,
    allow_loopback: bool = False,
    accept_statuses=(200,),
    not_found_is_none: bool = True,
):
    """
    GET or POST `url` and return its JSON body, or None.

    Returns None on a non-accepted status, a body that is not JSON, a body
    over `max_bytes`, a timeout, a connection error, or a blocked address.
    Redirects are followed only up to `max_redirects`, and every hop is
    judged like the first request.
    """
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    current = str(url)
    hops = 0

    try:
        check_url(current, allow_http=allow_http, allow_loopback=allow_loopback)

        async with aiohttp.ClientSession(
            timeout=client_timeout, connector=_connector(allow_loopback),
        ) as session:
            while True:
                async with session.request(
                    method, current, params=params if hops == 0 else None,
                    headers=headers, json=json_body, allow_redirects=False,
                ) as reply:
                    if reply.status in REDIRECT_STATUSES and reply.headers.get("Location"):
                        hops += 1
                        if hops > max_redirects:
                            logger.info("Outbound %s: too many redirects", url)
                            return None
                        current = urljoin(current, reply.headers["Location"])
                        check_url(current, allow_http=allow_http, allow_loopback=allow_loopback)
                        # A redirected POST is replayed as a GET, like a browser.
                        if reply.status == 303 or method.upper() == "POST":
                            method, json_body = "GET", None
                        continue

                    if reply.status == 404 and not_found_is_none:
                        return None

                    if reply.status not in accept_statuses:
                        logger.info("Outbound %s: status %s", url, reply.status)
                        return None

                    raw = await reply.content.read(max_bytes + 1)
                    if len(raw) > max_bytes:
                        logger.warning("Outbound %s: body over %d bytes", url, max_bytes)
                        return None

                    try:
                        return json.loads(raw.decode(reply.get_encoding() or "utf-8"))
                    except (ValueError, LookupError):
                        logger.info("Outbound %s: body is not JSON", url)
                        return None

    except BlockedAddressError as error:
        logger.warning("Outbound %s refused: %s", url, error)
        return None
    except (aiohttp.ClientError, TimeoutError, OSError) as error:
        logger.info("Outbound %s failed: %r", url, error)
        return None
