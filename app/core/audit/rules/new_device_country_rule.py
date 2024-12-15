from devkit.message import Message
from core.audit.events import ClientEvent, TransactionEvent
from core.messages.devices import msg_query_dvc_unregistered

from .base_rule import BaseRule


class NewDeviceCountryRule(BaseRule):
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

        visit_data = await self.scope.fetch_visit(self.event.visit_id)

        query_device = await self.scope.fetch_client_device_by_visit_id(
            visit_id=self.event.visit_id,
            application=self.application,
            client_id=norm_client_id.value,
        )

        if not query_device:
            return msg_query_dvc_unregistered.new(
                path="visit_id"
            )

        registered_countries = list({
            location["country"]
            for location in query_device.locations
        })

        if visit_data.country not in registered_countries:
            return (
                Message(
                    code="new_device_country",
                    path="visit_id",
                    context=dict(
                        new_country=visit_data.country,
                        registered_countries=registered_countries,
                    ),
                    text="Device is been used from an unrecognized country",
                )
            )
