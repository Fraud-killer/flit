from bootkit import undefined
from bootkit.struct import Struct
from core.guards import DeviceGuard
from core.models import Application
from core.devices.mezages import mzg_no_query_id_device
from core.applications.mezages import mzg_app_ref_exist
from core.devices.exceptions import NoQueryIdDeviceError
from bootkit.checks import is_uuid_string, is_dense_string
from bootkit.mezages import mzg_req_prop, mzg_uuid, mzg_dense_string
from core.devices.create_device_by_query_id import CreateDeviceByQueryId


class RegisterDeviceMarshal:
    def __init__(self, *, request):
        self.request = request

    def ensure_access(self, inputs):
        actor = self.request.auth
        application = inputs.application
        DeviceGuard(actor).can_create(application)

    def register_device(self, inputs):
        try:
            device = (
                CreateDeviceByQueryId(
                    end_user_id=inputs.end_user_id,
                    application=inputs.application,
                    query_id=inputs.device_query_id,
                )
                .call()
            )

            return (device, list())

        except NoQueryIdDeviceError: return (None, [
            mzg_no_query_id_device.new(target="device_query_id")
        ])

    def parse_inputs(self):
        end_user_id = self.request.data.get("end_user_id", undefined)
        application_id = self.request.data.get("application_id", undefined)
        device_query_id = self.request.data.get("device_query_id", undefined)

        errors = list()
        application = None

        if end_user_id is undefined:
            errors.append(
                mzg_req_prop.new(target="end_user_id")
            )
        elif not is_dense_string(end_user_id):
            errors.append(
                mzg_dense_string.new(target="end_user_id")
            )

        if device_query_id is undefined:
            errors.append(
                mzg_req_prop.new(target="device_query_id")
            )
        elif not is_dense_string(device_query_id):
            errors.append(
                mzg_dense_string.new(target="device_query_id")
            )

        if application_id is undefined:
            errors.append(
                mzg_req_prop.new(target="application_id")
            )
        elif not is_uuid_string(application_id):
            errors.append(
                mzg_uuid.new(target="application_id")
            )
        else:
            application = Application.objects.filter(
                id=application_id
            ).first()

            if not application:
                errors.append(
                    mzg_app_ref_exist.new(target="application_id")
                )

        inputs = None if errors else (
            Struct(
                end_user_id=end_user_id,
                application=application,
                device_query_id=device_query_id,
            )
        )

        return (inputs, errors)
