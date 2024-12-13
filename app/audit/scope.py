from core.models import Device
from fingerprint import FetchVisitData
from audit.lock_cache import LockCache, lockcache


class ScopeError(Exception):
    pass


class Scope(LockCache):
    def __init__(self, event, policy):
        self.event = event
        self.policy = policy

    @lockcache()
    async def fetch_device(self):
        visit_data = await self.fetch_visit_data()
        if visit_data is None: return None

        params = dict(
            end_user_id=self.event.client_id,
            fingerprint=visit_data.fingerprint,
            application=self.policy.application,
        )

        return Device.objects.filter(**params).first()

    @lockcache()
    async def fetch_visit_data(self):
        return FetchVisitData.call(self.event.device_query_id)
