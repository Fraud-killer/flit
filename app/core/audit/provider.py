from core.models import Device
from asgiref.sync import sync_to_async


class Provider:
    def __init__(self, data, policy):
        self.data = data
        self.policy = policy

    @sync_to_async
    def fetch_device(self, fingerprint):
        params = dict(
            fingerprint=fingerprint,
            end_user_id=self.data["end_user_id"],
            application = self.policy.application,
        )

        return Device.objects.filter(**params).first()

    @sync_to_async
    def fetch_device_location(self, device, country):
        return device.locations.filter(country__iexact=country).first()
