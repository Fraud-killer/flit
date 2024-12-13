import requests
from devkit.struct import Struct
from kernel.config import Config


class FetchVisitData:
    server_api_url = "https://api.fpjs.io"
    server_api_key = Config.fingerprint_server_api_key

    @classmethod
    def call(cls, request_id):
        visit_data = cls.make_request(request_id)
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
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()

        return response.json()["products"]

    @classmethod
    def normalize_visit_data(cls, visit_data):
        ip_data = visit_data["ipInfo"]["data"]
        ip_version = "v4" if "v4" in ip_data else "v6"
        geolocation = ip_data[ip_version]["geolocation"]
        identification = visit_data["identification"]["data"]

        return Struct(
            raw_data=visit_data,
            city=geolocation["city"]["name"],
            latitude=geolocation["latitude"],
            longitude=geolocation["longitude"],
            country=geolocation["country"]["name"],
            fingerprint=identification["visitorId"],
            state=geolocation["subdivisions"][0]["name"],
        )
