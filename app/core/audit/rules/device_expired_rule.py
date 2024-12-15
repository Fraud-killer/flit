from datetime import datetime
from devkit.message import Message
from core.audit.events import ClientEvent, TransactionEvent
from core.messages.devices import msg_query_dvc_unregistered

from .base_rule import BaseRule


class DeviceExpiredRule(BaseRule):
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
            return msg_query_dvc_unregistered.new(
                path="visit_id"
            )

        device_validity_days = self.policy.device_validity_days

        timezone = query_device.created_at.tzinfo
        delta = datetime.now(tz=timezone) - query_device.created_at

        if delta.days > device_validity_days:
            return (
                Message(
                    code="device_expired",
                    path="visit_id",
                    context=dict(
                        device_days=delta.days,
                        device_validity_days=device_validity_days,
                    ),
                    text="Device has reached the end of its validity period",
                )
            )
