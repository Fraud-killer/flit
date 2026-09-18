from secrets import token_urlsafe
from django.core.cache import cache
from django.utils import timezone
from asgiref.sync import async_to_sync

from core.models import Application
from core.intelligence.device_signals import consistency_flags
from core.intelligence.ip_intelligence import IPIntelligence
from core.services.identify_device import IdentifyDevice


class CollectVisit:
    """
    Turns signals from the FLIT browser SDK into a visit the audit pipeline
    can use later, addressed by a short-lived visit token.
    """

    VISIT_TTL_SECONDS = 30 * 60

    @classmethod
    def cache_key(cls, visit_token):
        return f"flit_visit:{visit_token}"

    @classmethod
    def call(cls, *, application: Application, signals, device_key=None, ip_address=None):
        ip_country_code = cls.ip_country_code(ip_address)

        identity, matched_by = IdentifyDevice.call(
            application=application,
            signals=signals,
            device_key=device_key,
        )

        flags = consistency_flags(signals, ip_country_code=ip_country_code)
        visit_token = token_urlsafe(24)

        visit = dict(
            device_key=identity.external_id,
            application_id=str(application.id),
            matched_by=matched_by,
            consistency_flags=flags,
            ip=ip_address,
            country_code=ip_country_code,
            user_agent=signals.get("user_agent"),
            timezone=signals.get("timezone"),
            collected_at=timezone.now().isoformat(),
        )

        cache.set(cls.cache_key(visit_token), visit, timeout=cls.VISIT_TTL_SECONDS)

        return visit_token, identity, visit

    @classmethod
    def fetch(cls, visit_token):
        return cache.get(cls.cache_key(visit_token))

    @classmethod
    def ip_country_code(cls, ip_address):
        if not ip_address:
            return None

        try:
            return async_to_sync(IPIntelligence.analyze)(ip_address).country_code
        except Exception:
            return None
