from devkit.struct import Struct
from core.models.device_identity import DeviceIdentitySource


def build_collected_visit(data):
    """
    A visit collected by the FLIT SDK, shaped like a Fingerprint visit so the
    rules do not care which source identified the device.
    """
    flags = data.get("consistency_flags") or []

    return Struct(
        raw_data=data,
        source=DeviceIdentitySource.FLIT,
        fingerprint=data.get("device_key"),
        matched_by=data.get("matched_by"),
        consistency_flags=flags,
        ip=data.get("ip"),
        user_agent=data.get("user_agent"),
        country=None,
        country_code=data.get("country_code"),
        city=None,
        state=None,
        latitude=None,
        longitude=None,
        # FLIT derives these itself; Fingerprint-only signals stay unset.
        asn=None,
        asn_org=None,
        is_datacenter=None,
        vpn=None,
        proxy=None,
        tor=None,
        ip_blocklisted=None,
        incognito=None,
        bot="bad" if "automation_markers" in flags else "notDetected",
        device_signals={},
        suspect_score=None,
    )
