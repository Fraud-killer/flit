from core.audit.events import ClientEvent, TransactionEvent
from core.messages.devices import msg_query_dvc_unregistered

from .base_rule import BaseRule


class UnregisteredDeviceRule(BaseRule):
    @property
    def applies(self):
        return (
            isinstance(self.event, ClientEvent)
            or isinstance(self.event, TransactionEvent)
        )

    async def perform(self):
        norm_client_id = self.normalize({
            ClientEvent: "id",
            TransactionEvent: "client_id",
        })

        self.ensure_present({
            norm_client_id.name: norm_client_id.value,
            "visit_id": self.event.visit_id,
        })

        query_device = await self.scope.fetch_client_device_by_visit_id(
            visit_id=self.event.visit_id,
            application=self.application,
            client_id=norm_client_id.value,
        )

        if not query_device:
            return msg_query_dvc_unregistered.new(path="visit_id")
