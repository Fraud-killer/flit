from core.models import Device
from core.services.fingerprint import FetchVisitData
from core.services.resolve_device_identity import ResolveDeviceIdentity


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

        device.identity = ResolveDeviceIdentity.call(
            visit=visit_data,
            application=application,
            client_id=client_id,
        )

        is_new_location = True

        for location in device.locations:
            if (
                location["city"] == visit_data.city
                and location["state"] == visit_data.state
                and location["country"] == visit_data.country
                and location["latitude"] == visit_data.latitude
                and location["longitude"] == visit_data.longitude
            ):
                is_new_location = False
                break

        if is_new_location:
            device.locations.insert(
                0,
                dict(
                    city=visit_data.city,
                    state=visit_data.state,
                    country=visit_data.country,
                    latitude=visit_data.latitude,
                    longitude=visit_data.longitude,
                )
            )

        device.full_clean()
        device.save()

        return device
