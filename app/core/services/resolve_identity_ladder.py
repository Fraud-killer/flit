"""
Build the identity ladder for an event and record what it links to.

Runs before the rules, so a rule that counts accounts on a key is counting
the current event too — the same ordering ResolveDeviceIdentity already uses.

A caller that is not recording the decision (a replay, a simulation) resolves
the ladder read-only: the keys are looked up so the rules can still reason
about them, but nothing is written, so re-scoring history cannot inflate the
very counts it is re-scoring.
"""

import logging

from asgiref.sync import sync_to_async
from django.db.models import F
from django.utils import timezone

from core.audit.identity_ladder import IdentityLadder
from core.intelligence import email_intelligence
from core.models.identity import IdentityKey, IdentityKeyType, IdentityAccountLink


logger = logging.getLogger(__name__)


def _global_key(key_type, value, preview, write):
    """The global IdentityKey node for a value, created only when writing."""
    value_hash = IdentityKey.hash_value(key_type, value)

    if not write:
        return IdentityKey.objects.filter(
            key_type=key_type, value_hash=value_hash,
        ).first()

    key, _ = IdentityKey.objects.get_or_create(
        key_type=key_type,
        value_hash=value_hash,
        defaults=dict(preview=preview or ""),
    )

    IdentityKey.objects.filter(pk=key.pk).update(
        event_count=F("event_count") + 1, last_seen_at=timezone.now(),
    )

    return key


def _resolve(ladder, key_type, value, preview, application, client_id, write):
    """Resolve one rung, and when writing, attach it to the account."""
    if not value:
        return

    key = _global_key(key_type, value, preview, write)

    if write and key is not None and client_id:
        link, _ = IdentityAccountLink.objects.get_or_create(
            identity_key=key, application=application, client_id=client_id,
        )
        IdentityAccountLink.objects.filter(pk=link.pk).update(
            event_count=F("event_count") + 1, last_seen_at=timezone.now(),
        )

    ladder.add(key_type, value, key=key)


class ResolveIdentityLadder:
    @classmethod
    def call(cls, *, application, client_id, device_identity=None, email=None,
             ip_address=None, asn=None, signature_hash=None, write=True):
        ladder = IdentityLadder()

        # The device rung stores no links of its own: they already live in
        # DeviceAccountLink, written by ResolveDeviceIdentity, and a second
        # copy here would be one more thing to keep in step. It does still get
        # a global key node, because a device fingerprint is the single most
        # valuable thing the shared network can hold reputation against.
        if device_identity is not None:
            ladder.add(
                IdentityKeyType.DEVICE,
                device_identity.external_id,
                key=device_identity,
                network_key=_global_key(
                    IdentityKeyType.DEVICE,
                    device_identity.external_id,
                    f"device:{device_identity.external_id[:16]}",
                    write,
                ),
            )

        rungs = []

        if signature_hash:
            rungs.append(
                (IdentityKeyType.SIGNATURE, signature_hash, f"sig:{signature_hash[:12]}")
            )

        if email:
            root = email_intelligence.normalize_email(email)
            if root:
                rungs.append(
                    (IdentityKeyType.EMAIL_ROOT, root, email_intelligence.redact(root))
                )

        if ip_address:
            rungs.append((IdentityKeyType.IP, ip_address, str(ip_address)))

        if asn:
            rungs.append((IdentityKeyType.ASN, asn, str(asn)))

        for key_type, value, preview in rungs:
            _resolve(ladder, key_type, value, preview, application, client_id, write)

        return ladder


async def resolve_identity_ladder(
    *, event, policy, scope, visit, device_identity, write=True,
):
    """
    The async entry point the Auditor uses.

    Enrichment that needs the network (ASN lookup) happens here; the database
    work is handed to the synchronous resolver above. Like the rest of FLIT's
    intelligence, a failure here degrades the decision rather than failing it.
    """
    from core.audit.rules.visit_signals import event_value

    ip_address = event_value(event, "ip_address") or getattr(visit, "ip", None)
    email = event_value(event, "email")
    asn = getattr(visit, "asn", None)
    signature_hash = getattr(visit, "signature_hash", None)

    # An attacker who rotates IPs usually cannot rotate the hosting provider
    # behind them, so the ASN is worth resolving even with no visit data.
    if not asn and ip_address:
        try:
            from core.intelligence.ip_intelligence import IPIntelligence

            info = await IPIntelligence.analyze(ip_address)
            asn = getattr(info, "asn", None)
        except Exception:
            logger.debug("Could not resolve ASN for identity ladder", exc_info=True)

    try:
        return await sync_to_async(ResolveIdentityLadder.call)(
            application=policy.application,
            client_id=event.account_id,
            device_identity=device_identity,
            email=email,
            ip_address=ip_address,
            asn=asn,
            signature_hash=signature_hash,
            write=write,
        )
    except Exception:
        logger.warning("Could not resolve identity ladder", exc_info=True)

        # Fall back to a ladder that knows what the event produced but is
        # linked to nothing. Coverage still reports honestly, while the
        # correlation and network rules find no keys — which is correct: the
        # store they would have read is the one that just failed.
        ladder = IdentityLadder()

        for key_type, value in (
            (IdentityKeyType.DEVICE, getattr(device_identity, "external_id", None)),
            (IdentityKeyType.EMAIL_ROOT, email_intelligence.normalize_email(email or "")),
            (IdentityKeyType.IP, ip_address),
            (IdentityKeyType.ASN, asn),
        ):
            if value:
                ladder.add(key_type, value, key=None, network_key=None)

        return ladder
