from core.models import Device
from asgiref.sync import sync_to_async
from services.fingerprint import FetchVisitData
from audit.lock_cache import LockCache, lockcache


class ScopeError(Exception):
    pass


class Scope(LockCache):
    def __init__(self, event, policy):
        self.event = event
        self.policy = policy

    @lockcache()
    async def fetch_visit_data(self):
        return await FetchVisitData.async_call(
            self.event.device_query_id
        )

    @lockcache()
    async def fetch_device(self):
        visit_data = await self.fetch_visit_data()
        if visit_data is None: return None

        queryset = (
            Device.objects.filter(
                client_id=self.event.client_id,
                fingerprint=visit_data.fingerprint,
                application=self.policy.application,
            )
        )

        return await sync_to_async(queryset.first)()
