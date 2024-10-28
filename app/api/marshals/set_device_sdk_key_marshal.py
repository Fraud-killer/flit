from bootkit.casts import to_bool
from bootkit.struct import Struct
from core.models import Application
from core.guards import ApplicationGuard
from bootkit.mezages import mzg_uuid, mzg_to_bool
from core.applications.mezages import mzg_app_ref_exist
from bootkit.checks import is_uuid_string, resolves_to_bool
from core.applications.mezages import mzg_app_has_device_sdk_key
from core.applications.exceptions import AppHasDeviceSdkKeyError
from core.applications.set_app_device_sdk_key import SetAppDeviceSdkKey


class SetDeviceSdkKeyMarshal:
    def __init__(self, *, id, request):
        self.id = id
        self.request = request        

    def ensure_access(self, inputs):
        actor = self.request.auth
        resource = inputs.application
        ApplicationGuard(actor, resource).can_manage()

    def set_device_sdk_key(self, inputs):
        try:
            token = (
                SetAppDeviceSdkKey(
                    reset=inputs.reset,
                    application=inputs.application,
                )
                .call()
            )

            return (token, list())

        except AppHasDeviceSdkKeyError: return (None, [
            mzg_app_has_device_sdk_key.new(target="id")
        ])

    def parse_inputs(self):
        errors = list()
        application = None

        reset = self.request.query_params.get("reset")

        if not resolves_to_bool(reset):
            errors.append(mzg_to_bool.new(target="reset"))

        if not is_uuid_string(self.id):
            errors.append(mzg_uuid.new(target="id"))
        else:
            application = Application.objects.filter(
                id=self.id
            ).first()

            if not application:
                errors.append(mzg_app_ref_exist.new(target="id"))

        inputs = None if errors else (
            Struct(
                reset=to_bool(reset),
                application=application,
            )
        )

        return (inputs, errors)
