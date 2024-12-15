from core.models import Device
from asgiref.sync import sync_to_async
from core.services.fingerprint import FetchVisitData
from core.audit.lock_cache import LockCache, lockcache


class Scope(LockCache):
    @lockcache(lambda visit_id: visit_id)
    async def fetch_visit(self, visit_id):
        return await FetchVisitData.async_call(
            visit_id
        )

    @lockcache(
        lambda *, visit_id, client_id, application: (
            f"{visit_id}:{client_id}:{application.id}"
        )
    )
    async def fetch_client_device_by_visit_id(
        self, *, visit_id, client_id, application
    ):
        visit = await self.fetch_visit(visit_id)
        if visit is None: return None

        queryset = (
            Device.objects.filter(
                client_id=client_id,
                application=application,
                fingerprint=visit.fingerprint,
            )
        )

        return await sync_to_async(queryset.first)()
