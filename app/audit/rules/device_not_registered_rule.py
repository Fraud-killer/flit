from devkit import undefined
from devkit.messages import msg_present
from audit.events import ClientEvent, TransactionEvent
from core.messages.audits import msg_device_not_registered

from .base_rule import BaseRule


class DeviceNotRegisteredRule(BaseRule):
    @property
    def applies(self):
        return (
            isinstance(self.scope.event, ClientEvent)
            or isinstance(self.scope.event, TransactionEvent)
        )

    async def perform(self):
        if self.scope.event.device_query_id in (None, undefined):
            return msg_present.new(path="device_query_id")

        device = await self.scope.fetch_device()
        if not device: return msg_device_not_registered
