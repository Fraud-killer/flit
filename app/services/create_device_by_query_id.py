from core.models import Device
from services.fingerprint import FetchVisitData


class QueryIdDeviceNotFound(Exception):
    pass


class CreateDeviceByQueryId:
    @classmethod
    def call(cls, *, query_id, client_id, application):
        visit_data = FetchVisitData.call(query_id)

        if visit_data is None:
            raise QueryIdDeviceNotFound(query_id)

        device = (
            Device.objects.filter(
                client_id=client_id,
                application=application,
                fingerprint=visit_data.fingerprint,
            )
            .first()
        )

        if not device:
            device = Device(
                client_id=client_id,
                application=application,
                raw_data=visit_data.raw_data,
                fingerprint=visit_data.fingerprint,
            )

        locations = [
            dict(
                city=visit_data.city,
                state=visit_data.state,
                country=visit_data.country,
                latitude=visit_data.latitude,
                longitude=visit_data.longitude,
            )
        ]

        for location in device.locations:
            if (
                location["city"] == visit_data.city
                and location["state"] == visit_data.state
                and location["country"] == visit_data.country
                and location["latitude"] == visit_data.latitude
                and location["longitude"] == visit_data.longitude
            ):
                continue

            locations.append(location)

        device.locations = locations
        device.full_clean()
        device.save()

        return device
