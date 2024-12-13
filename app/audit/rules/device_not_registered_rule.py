from devkit import undefined
from devkit.message import Message
from audit.events import ClientEvent, TransactionEvent

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
            return (
                # TODO: Refine the below message for reuse
                Message(
                    code="present",
                    path="device_query_id",
                    text="Some texts that will be refined goes here",
                )
            )

        if not await self.scope.fetch_device():
            return (
                # TODO: Refine the below message for reuse
                Message(
                    code="device_not_registered",
                    text="Some texts that will be refined later goes here",
                )
            )
