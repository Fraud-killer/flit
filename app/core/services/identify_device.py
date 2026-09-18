from datetime import timedelta
from django.db.models import F
from django.utils import timezone

from core.models import DeviceIdentity, DeviceSignature
from core.models.device_identity import DeviceIdentitySource
from core.intelligence.device_signals import (
    normalize,
    signature_hash,
    similarity,
)


class IdentifyDevice:
    """
    Resolves collected signals to a DeviceIdentity.

    Three ways to recognise a device, strongest first:
      1. the exact same signature has been seen for this application
      2. the browser returned a device key FLIT issued, and its signals are
         still broadly similar (survives a browser update changing a hash)
      3. a stored signature is similar enough to be the same device
    Otherwise the device is new.
    """

    # Fingerprints drift, so an exact match cannot be required. At this
    # threshold one heavy component (canvas, WebGL) may change and the device
    # is still recognised; two may not.
    SIMILARITY_THRESHOLD = 0.8

    # A device key is a claim, not proof: it can be copied between browsers.
    # It only settles identity when the signals broadly agree.
    HINT_THRESHOLD = 0.5

    CANDIDATE_LIMIT = 200
    CANDIDATE_MAX_AGE_DAYS = 90

    @classmethod
    def call(cls, *, application, signals, device_key=None):
        components = normalize(signals)
        fingerprint = signature_hash(components)

        identity, matched_by = cls.match(
            application=application,
            components=components,
            fingerprint=fingerprint,
            device_key=device_key,
        )

        if identity is None:
            identity = DeviceIdentity.objects.create(
                source=DeviceIdentitySource.FLIT,
                external_id=DeviceIdentity.generate_external_id(),
            )
            matched_by = "new"

        cls.store_signature(
            identity=identity,
            application=application,
            components=components,
            fingerprint=fingerprint,
        )

        return identity, matched_by

    @classmethod
    def match(cls, *, application, components, fingerprint, device_key):
        exact = DeviceSignature.objects.filter(
            application=application,
            signature_hash=fingerprint,
        ).first()

        if exact:
            return exact.device, "signature"

        if device_key:
            identity = DeviceIdentity.objects.filter(
                source=DeviceIdentitySource.FLIT,
                external_id=device_key,
            ).first()

            if identity and cls.best_similarity(identity, application, components) >= cls.HINT_THRESHOLD:
                return identity, "device_key"

        candidate, score = cls.nearest(application, components)

        if candidate and score >= cls.SIMILARITY_THRESHOLD:
            return candidate.device, "similarity"

        return None, None

    @classmethod
    def best_similarity(cls, identity, application, components):
        scores = [
            similarity(components, signature.components)
            for signature in identity.signatures.filter(application=application)
        ]
        return max(scores, default=0.0)

    @classmethod
    def nearest(cls, application, components):
        candidates = (
            DeviceSignature.objects
            .filter(
                application=application,
                platform=components.get("platform", ""),
                last_seen_at__gte=timezone.now() - timedelta(days=cls.CANDIDATE_MAX_AGE_DAYS),
            )
            .order_by("-last_seen_at")[:cls.CANDIDATE_LIMIT]
        )

        best = None
        best_score = 0.0

        for candidate in candidates:
            score = similarity(components, candidate.components)
            if score > best_score:
                best, best_score = candidate, score

        return best, best_score

    @classmethod
    def store_signature(cls, *, identity, application, components, fingerprint):
        signature, created = DeviceSignature.objects.get_or_create(
            application=application,
            signature_hash=fingerprint,
            defaults=dict(
                device=identity,
                components=components,
                platform=components.get("platform", ""),
            ),
        )

        DeviceSignature.objects.filter(pk=signature.pk).update(
            components=components,
            event_count=F("event_count") + 1,
            last_seen_at=timezone.now(),
        )

        return signature
