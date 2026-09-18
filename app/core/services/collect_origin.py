"""
Per-application origin allowlist for the public collection endpoint.

The endpoint cannot be authenticated, because browsers call it directly, so
the allowlist limits which sites may use an application's collection key.

It is enforced by the browser, not by trust: a request with no Origin header
(a server, a native app, curl) is allowed through. The allowlist stops
another *website* from using your key in its pages; it is not a defence
against a server forging requests, which rate limiting and the fact that the
key authorises nothing already cover.
"""

import re
from urllib.parse import urlsplit


ORIGIN_PATTERN = re.compile(r"^https?://(\*\.)?[a-z0-9.-]+(:\d+)?$")


def normalize_origin(value):
    """'HTTPS://Shop.Example.com/' -> 'https://shop.example.com'."""
    if not isinstance(value, str) or not value.strip():
        return None

    value = value.strip().rstrip("/")
    parts = urlsplit(value)

    if not parts.scheme or not parts.netloc:
        return None

    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


def is_collect_origin(value):
    """An allowlist entry: an origin, optionally with a `*.` subdomain wildcard."""
    if not isinstance(value, str):
        return False

    # An origin has no path, query or fragment; rejecting them keeps a
    # mistyped entry from silently matching more than it looks like it does.
    parts = urlsplit(value.strip().rstrip("/"))
    if parts.path or parts.query or parts.fragment:
        return False

    normalized = normalize_origin(value)
    return bool(normalized and ORIGIN_PATTERN.match(normalized))


def origin_matches(pattern, origin):
    pattern = normalize_origin(pattern)
    origin = normalize_origin(origin)

    if not pattern or not origin:
        return False

    if pattern == origin:
        return True

    if "://*." not in pattern:
        return False

    # https://*.example.com matches any subdomain, not example.com itself.
    prefix, _, suffix = pattern.partition("://*.")
    return origin.startswith(f"{prefix}://") and origin.endswith(f".{suffix}")


def is_origin_allowed(application, origin):
    """
    True when the origin may use this application's collection key.

    An application with no configured origins accepts any, so an integration
    keeps working until the merchant locks it down.
    """
    allowed = getattr(application, "collect_origins", None) or []

    if not allowed:
        return True

    if not origin:
        return True

    return any(origin_matches(pattern, origin) for pattern in allowed)


def cors_headers(origin=None):
    """
    Reflect the calling origin so a locked-down application does not hand a
    wildcard to every site. Falls back to `*` for callers without an Origin.
    """
    return {
        "Access-Control-Allow-Origin": normalize_origin(origin) or "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin",
    }
