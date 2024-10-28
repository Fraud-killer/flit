from django.db import transaction
from bootkit.struct import Struct
from core.fingerprint import Fingerprint
from core.models import Device, DeviceLocation
from core.devices.mezages import mzg_no_query_id_device
from core.devices.exceptions import NoQueryIdDeviceError


class CreateDeviceByQueryId:
    @classmethod
    def exec(cls, **kwargs):
        return cls(**kwargs).call()

    def __init__(self, *, query_id, application, end_user_id):
        self.query_id = query_id
        self.end_user_id = end_user_id
        self.application = application

    def call(self):
        visit_data = Fingerprint.fetch_visit(self.query_id)

        if visit_data is None:
            raise NoQueryIdDeviceError(mzg_no_query_id_device.text)

        normalized_data = self.normalize_visit_data(visit_data)
        device, location = self.fetch_existing_records(normalized_data)

        with transaction.atomic():
            if not device:
                device = Device(
                    raw_data=visit_data,
                    application=self.application,
                    end_user_id=self.end_user_id,
                    fingerprint=normalized_data.fingerprint,
                )

                device.full_clean()
                device.save()

            if not location:
                location = DeviceLocation(
                    device=device,
                    city=normalized_data.city,
                    state=normalized_data.state,
                    country=normalized_data.country,
                    latitude=normalized_data.latitude,
                    longitude=normalized_data.longitude,
                )

                location.full_clean()
                location.save()

        return device

    def normalize_visit_data(self, visit_data):
        ip_data = visit_data["ipInfo"]["data"]
        ip_version = "v4" if "v4" in ip_data else "v6"
        geolocation = ip_data[ip_version]["geolocation"]
        identification = visit_data["identification"]["data"]

        return Struct(
            city=geolocation["city"]["name"],
            latitude=geolocation["latitude"],
            longitude=geolocation["longitude"],
            country=geolocation["country"]["name"],
            fingerprint=identification["visitorId"],
            state=geolocation["subdivisions"][0]["name"],
        )

    def fetch_existing_records(self, normalized_data):
        location = None

        device = Device.objects.filter(
            application=self.application,
            end_user_id=self.end_user_id,
            fingerprint=normalized_data.fingerprint,
        ).first()

        if device:
            location = DeviceLocation.objects.filter(
                device=device,
                city__iexact=normalized_data.city,
                state__iexact=normalized_data.state,
                country__iexact=normalized_data.country,
                latitude=normalized_data.latitude,
                longitude=normalized_data.longitude,
            ).first()

        return (device, location)
