from bootkit import undefined
from core.fingerprint import Fingerprint

from .base_rule import BaseRule


class NewDeviceRule(BaseRule):
    async def exert(self):
        device_query_id = self.data.get("device_query_id", undefined)

        if device_query_id is undefined:
            return ["Device query id was not provided"]

        if device_query_id is None:
            return ["Device query id was found to be null"]

        visit_data = Fingerprint.fetch_visit(device_query_id)

        if visit_data is None:
            return ["Could not find the device with the query id provided"]

        fingerprint = visit_data["identification"]["data"]["visitorId"]

        if not await self.provider.fetch_device(fingerprint):
            return ["The device with the query id provided is not recognised"]
