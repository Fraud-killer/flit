from http import HTTPMethod
from django.utils import timezone
from core.audit.auditor import Auditor
from asgiref.sync import async_to_sync
from api.base import build_api_response
from api.parsers import parse_audit_inputs
from rest_framework.viewsets import ViewSet
from api.permissions import HasAuthenticated
from rest_framework.decorators import action
from core.guards import DeviceGuard, ApplicationGuard
from api.parsers import parse_register_device_inputs
from api.parsers import parse_outcome_inputs, parse_device_lookup_inputs
from core.services.describe_device import DescribeDevice
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

    @action(
        detail=True,
        methods=[HTTPMethod.POST],
        url_path=r"outcomes",
    )
    def outcomes(self, request, pk):
        inputs, errors = parse_outcome_inputs(pk, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        audit_log = inputs.audit_log
        audit_log.label = inputs.label
        audit_log.labeled_at = timezone.now()
        audit_log.save(update_fields=["label", "labeled_at"])

        return build_api_response(
            data=dict(
                audit_id=str(audit_log.id),
                event_id=audit_log.resource_id,
                label=audit_log.label,
                labeled_at=audit_log.labeled_at,
            )
        )

    @action(
        detail=True,
        methods=[HTTPMethod.GET],
        url_path=r"devices/(?P<device_id>[^/.]+)",
    )
    def device(self, request, pk, device_id=None):
        inputs, errors = parse_device_lookup_inputs(pk, device_id)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        device = DescribeDevice.call(
            device=inputs.device,
            application=inputs.application,
        )

        return build_api_response(data=dict(device=device))
