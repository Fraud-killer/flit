from bootkit import undefined
from core.fingerprint import Fingerprint

from .base_rule import BaseRule


class NewDeviceCountryRule(BaseRule):
    async def exert(self):        
        device_query_id = self.data.get("device_query_id", undefined)
        if device_query_id in (None, undefined): return None

        visit_data = Fingerprint.fetch_visit(device_query_id)
        if visit_data is None: return None

        identification = visit_data["identification"]["data"]
        fingerprint = identification["visitorId"]

        device = await self.provider.fetch_device(fingerprint)
        if device is None: return None

        ip_data = visit_data["ipInfo"]["data"]
        ip_version = "v4" if "v4" in ip_data else "v6"
        geolocation = ip_data[ip_version]["geolocation"]
        country = geolocation["country"]["name"]

        location = await self.provider.fetch_device_location(device, country)

        if location is None: return ["The device ip address country is not recognised"]
 