from http import HTTPMethod
from core.audit.auditor import Auditor
from asgiref.sync import async_to_sync
from api.base import build_api_response
from api.parsers import parse_audit_inputs
from rest_framework.viewsets import ViewSet
from api.permissions import HasAuthenticated
from rest_framework.decorators import action
from core.guards import DeviceGuard, ApplicationGuard
from api.parsers import parse_register_device_inputs
from core.messages.devices import msg_no_query_id_device
from api.serializers.device_serializers import DeviceSerializer
from core.services.create_device_by_query_id import CreateDeviceByQueryId, QueryIdDeviceNotFound


class ApplicationViewSet(ViewSet):
    permission_classes = [HasAuthenticated]

    @action(
        detail=True,
        methods=[HTTPMethod.POST],
        url_path=r"audit-(?P<mode>.+)",
    )
    def audit(self, request, pk, mode=None):
        inputs, errors = parse_audit_inputs(pk, mode, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        result = async_to_sync(Auditor.audit)(inputs.event, inputs.policy)

        return build_api_response(data=dict(result))

    @action(
        detail=True,
        methods=[HTTPMethod.POST],
        url_path=r"register-device",
    )
    def register_device(self, request, pk):
        inputs, errors = parse_register_device_inputs(pk, request)
        if errors: return build_api_response(errors=errors)

        DeviceGuard(request.auth).can_create(inputs.application)

        try:
            device = (
                CreateDeviceByQueryId.call(
                    client_id=inputs.client_id,
                    application=inputs.application,
                    query_id=inputs.visit_id,
                )
            )
        except QueryIdDeviceNotFound:
            error = msg_no_query_id_device.new(path="visit_id")
            return build_api_response(errors=[error])

        return build_api_response(data=dict(device=DeviceSerializer(device).data))
