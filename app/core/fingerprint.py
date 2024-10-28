import requests
from core.config import Config


class Fingerprint:
    server_api_url = "https://api.fpjs.io"
    server_api_key = Config.fingerprint_server_api_key
    management_api_url = "https://management-api.fpjs.io"
    management_api_key = Config.fingerprint_management_api_key

    @classmethod
    def fetch_visit(cls, request_id):
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
    def delete_public_key(cls, id):
        response = requests.delete(
            f"{cls.management_api_url}/api-keys/{id}",
            headers={
                "accept": "application/json",
                "x-api-version": "2024-05-20",
                "content-type": "application/json",
                "authorization": f"Bearer {cls.management_api_key}",
            },
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()

    @classmethod
    def create_public_key(cls, name):
        response = requests.post(
            f"{cls.management_api_url}/api-keys",
            json={
                "name": name,
                "type": "public",
            },
            headers={
                "accept": "application/json",
                "x-api-version": "2024-05-20",
                "content-type": "application/json",
                "authorization": f"Bearer {cls.management_api_key}",
            },
        )

        response.raise_for_status()

        data = response.json()["data"]

        return dict(id=data["id"], name=data["name"], token=data["token"])
