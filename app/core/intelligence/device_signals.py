"""
Normalisation and consistency checks for signals collected by the FLIT
browser SDK.

Only hashes and coarse values are kept: a device is recognised by comparing
hashed components, never by storing raw canvas images or font lists.
"""

import re
import hashlib
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from datetime import datetime


# Components compared when matching a device, and how much each one counts.
# Rendering components are heaviest: they are the hardest to change by hand.
COMPONENT_WEIGHTS = {
    "canvas": 3,
    "webgl": 3,
    "webgl_renderer": 2,
    "audio": 2,
    "fonts": 2,
    "screen": 1,
    "timezone": 1,
    "languages": 1,
    "platform": 1,
    "hardware": 1,
    "ua_brand": 1,
}

# Components a device keeps across sessions, hashed into its signature.
STABLE_COMPONENTS = [
    "canvas",
    "webgl",
    "webgl_renderer",
    "audio",
    "fonts",
    "platform",
    "hardware",
    "screen",
]

SOFTWARE_RENDERERS = ("swiftshader", "llvmpipe", "softpipe", "mesa offscreen", "virgl")

MOBILE_UA_PATTERN = re.compile(r"android|iphone|ipad|ipod|mobile", re.I)

PLATFORM_KEYWORDS = {
    "windows": ("win",),
    "macos": ("mac",),
    "linux": ("linux", "x11"),
    "android": ("android",),
    "ios": ("iphone", "ipad", "ipod", "ios"),
}


def digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:32]


def normalize(signals):
    """Collected signals -> the component map used for matching."""
    signals = signals or {}
    screen = signals.get("screen") or {}

    return {
        "canvas": digest(signals.get("canvas")),
        "webgl": digest(signals.get("webgl")),
        "webgl_renderer": digest(signals.get("webgl_renderer")),
        "audio": digest(signals.get("audio")),
        "fonts": digest(signals.get("fonts")),
        "screen": digest([
            screen.get("width"),
            screen.get("height"),
            screen.get("color_depth"),
            screen.get("pixel_ratio"),
        ]),
        "timezone": str(signals.get("timezone") or ""),
        "languages": digest(signals.get("languages")),
        "platform": platform_family(signals),
        "hardware": digest([
            signals.get("hardware_concurrency"),
            signals.get("device_memory"),
            signals.get("touch_points"),
        ]),
        "ua_brand": digest(signals.get("ua_brands")),
    }


def platform_family(signals):
    """A coarse OS family, used to avoid comparing a phone with a desktop."""
    haystack = " ".join(
        str(signals.get(name) or "")
        for name in ("platform", "ua_platform", "user_agent")
    ).lower()

    for family, keywords in PLATFORM_KEYWORDS.items():
        if any(keyword in haystack for keyword in keywords):
            return family

    return "unknown"


def signature_hash(components):
    return hashlib.sha256(
        "|".join(f"{name}={components.get(name, '')}" for name in STABLE_COMPONENTS).encode()
    ).hexdigest()


def similarity(left, right):
    """Weighted fraction of components two signature snapshots share (0-1)."""
    total = 0
    matched = 0

    for name, weight in COMPONENT_WEIGHTS.items():
        left_value = left.get(name)
        right_value = right.get(name)

        if not left_value or not right_value:
            continue

        total += weight
        if left_value == right_value:
            matched += weight

    return matched / total if total else 0.0


def consistency_flags(signals, *, ip_country_code=None):
    """
    Cheap server-side checks a spoofed browser tends to fail. They compare
    signals against each other, so they cannot be defeated by editing one
    value alone.
    """
    signals = signals or {}
    flags = []

    if timezone_is_spoofed(signals):
        flags.append("spoofed_timezone")

    if platform_is_inconsistent(signals):
        flags.append("platform_mismatch")

    renderer = str(signals.get("webgl_renderer") or "").lower()
    if renderer and any(name in renderer for name in SOFTWARE_RENDERERS):
        flags.append("software_renderer")

    if automation_markers(signals):
        flags.append("automation_markers")

    if device_class_is_inconsistent(signals):
        flags.append("device_class_mismatch")

    if locale_country_differs(signals, ip_country_code):
        flags.append("locale_country_mismatch")

    return flags


def timezone_is_spoofed(signals):
    """The reported UTC offset must match the reported IANA zone."""
    name = signals.get("timezone")
    offset = signals.get("timezone_offset")

    if not name or offset is None:
        return False

    try:
        zone = ZoneInfo(str(name))
    except (ZoneInfoNotFoundError, ValueError):
        return True

    try:
        reported_minutes = int(offset)
    except (TypeError, ValueError):
        return True

    utc_offset = datetime.now(zone).utcoffset()
    actual_minutes = -int(utc_offset.total_seconds() // 60)

    # getTimezoneOffset() is minutes behind UTC, so it is the negated offset.
    return reported_minutes != actual_minutes


def platform_is_inconsistent(signals):
    """navigator.platform, userAgentData.platform and the UA must agree."""
    families = {
        platform_family({"platform": signals.get("platform")}),
        platform_family({"platform": signals.get("ua_platform")}),
        platform_family({"platform": signals.get("user_agent")}),
    }
    families.discard("unknown")

    return len(families) > 1


def automation_markers(signals):
    if signals.get("webdriver"):
        return True

    empty_environment = (
        not signals.get("languages")
        and not signals.get("plugins")
    )

    return bool(
        empty_environment
        or signals.get("hardware_concurrency") == 0
        or (signals.get("screen") or {}).get("width") == 0
    )


def device_class_is_inconsistent(signals):
    """A phone UA with no touch points, or a desktop UA reporting many."""
    user_agent = str(signals.get("user_agent") or "")
    touch_points = signals.get("touch_points")

    if not user_agent or touch_points is None:
        return False

    looks_mobile = bool(MOBILE_UA_PATTERN.search(user_agent))

    return looks_mobile != (int(touch_points) > 0)


def locale_country_differs(signals, ip_country_code):
    """A weak signal on its own: travellers and expats trip it legitimately."""
    if not ip_country_code:
        return False

    languages = signals.get("languages") or []
    regions = {
        str(language).replace("_", "-").split("-")[1].upper()
        for language in languages
        if "-" in str(language).replace("_", "-")
    }

    return bool(regions) and ip_country_code.upper() not in regions
