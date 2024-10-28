from bootkit import undefined
from datetime import datetime
from core.fingerprint import Fingerprint

from .base_rule import BaseRule


class ExpiredDeviceRule(BaseRule):
    async def exert(self):        
        device_query_id = self.data.get("device_query_id", undefined)
        if device_query_id in (None, undefined): return None

        visit_data = Fingerprint.fetch_visit(device_query_id)
        if visit_data is None: return None

        fingerprint = visit_data["identification"]["data"]["visitorId"]
        device = await self.provider.fetch_device(fingerprint)
        if device is None: return None

        tzinfo = device.created_at.tzinfo
        delta = datetime.now(tzinfo) - device.created_at

        if delta.days <= 90: return None
        return ["The device with the query id provided has expired"]
 