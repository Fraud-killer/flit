import requests
from kernel.config import Config
from devkit.struct import Struct


class CreatePublicKey:
    api_url = "https://management-api.fpjs.io"
    api_key = Config.fingerprint_management_api_key

    @classmethod
    def call(cls, name):
        response = requests.post(
            f"{cls.api_url}/api-keys",
            json={
                "name": name,
                "type": "public",
            },
            headers={
                "accept": "application/json",
                "x-api-version": "2024-05-20",
                "content-type": "application/json",
                "authorization": f"Bearer {cls.api_key}",
            },
        )

        response.raise_for_status()

        data = response.json()["data"]

        return Struct(id=data["id"], name=data["name"], token=data["token"])
