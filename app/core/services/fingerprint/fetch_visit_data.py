import requests
from devkit.struct import Struct
from kernel.config import Config
from aiohttp import ClientSession, ClientTimeout


class FetchVisitData:
    server_api_url = "https://api.fpjs.io"
    server_api_key = Config.fingerprint_server_api_key
    timeout_seconds = 5

    @classmethod
    def call(cls, request_id):
        visit_data = cls.make_request(request_id)
        if visit_data is None: return None
        return cls.normalize_visit_data(visit_data)

    @classmethod
    async def async_call(cls, request_id):
        visit_data = await cls.async_make_request(request_id)
        if visit_data is None: return None
        return cls.normalize_visit_data(visit_data)

    @classmethod
    def make_request(cls, request_id):
        response = requests.get(
            f"{cls.server_api_url}/events/{request_id}",
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "auth-api-key": cls.server_api_key,
            },
            timeout=cls.timeout_seconds,
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()

        return response.json()["products"]

    @classmethod
    async def async_make_request(cls, request_id):
        url = f"{cls.server_api_url}/events/{request_id}"

        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "auth-api-key": cls.server_api_key,
        }

        timeout = ClientTimeout(total=cls.timeout_seconds)

        async with ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 404:
                    return None

                response.raise_for_status()

                return (await response.json())["products"]

    @classmethod
    def normalize_visit_data(cls, visit_data):
        ip_data = visit_data["ipInfo"]["data"]
        ip_version = "v4" if "v4" in ip_data else "v6"
        ip_info = ip_data[ip_version]
        geolocation = ip_info["geolocation"]
        identification = visit_data["identification"]["data"]
        asn = ip_info.get("asn") or {}
        datacenter = ip_info.get("datacenter") or {}
        bot_result = cls.product_result(visit_data, "botd", "bot")

        return Struct(
            raw_data=visit_data,
            city=geolocation["city"]["name"],
            latitude=geolocation["latitude"],
            longitude=geolocation["longitude"],
            country=geolocation["country"]["name"],
            fingerprint=identification["visitorId"],
            state=geolocation["subdivisions"][0]["name"],
            ip=ip_info.get("address") or identification.get("ip"),
            user_agent=(identification.get("browserDetails") or {}).get("userAgent"),
            asn=asn.get("asn"),
            asn_org=asn.get("name"),
            is_datacenter=datacenter.get("result"),
            # Smart Signals; None when the product is not enabled on the plan
            vpn=cls.product_result(visit_data, "vpn"),
            proxy=cls.product_result(visit_data, "proxy"),
            tor=cls.product_result(visit_data, "tor"),
            ip_blocklisted=cls.product_result(visit_data, "ipBlocklist"),
            incognito=cls.product_result(visit_data, "incognito"),
            # "notDetected", "good" (e.g. search engines) or "bad"
            bot=bot_result.get("result") if isinstance(bot_result, dict) else None,
        )

    @staticmethod
    def product_result(visit_data, product, field="result"):
        data = (visit_data.get(product) or {}).get("data") or {}
        return data.get(field)
