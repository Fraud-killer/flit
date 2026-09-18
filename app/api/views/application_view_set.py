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
from core.models import Case, CaseNote, CaseStatus
from api.parsers import parse_register_device_inputs
from api.parsers import parse_outcome_inputs, parse_device_lookup_inputs
from core.services.describe_device import DescribeDevice
from core.services.list_decisions import ListDecisions
from core.services.simulate_policy import SimulatePolicy
from api.parsers import parse_decision_filters, parse_case_inputs, parse_simulation_inputs
from api.serializers.case_serializers import serialize_case
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

    @action(
        detail=True,
        methods=[HTTPMethod.GET],
        url_path=r"decisions",
    )
    def decisions(self, request, pk):
        inputs, errors = parse_decision_filters(pk, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        return build_api_response(
            data=ListDecisions.call(application=inputs.application, filters=inputs),
        )

    @action(
        detail=True,
        methods=[HTTPMethod.GET],
        url_path=r"cases",
    )
    def cases(self, request, pk):
        inputs, errors = parse_decision_filters(pk, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        status_filter = request.query_params.get("status", CaseStatus.OPEN)

        cases = (
            Case.objects
            .filter(application=inputs.application)
            .select_related("audit_log", "assignee")
        )

        if status_filter != "all":
            cases = cases.filter(status=status_filter)

        total = cases.count()
        page = cases[inputs.offset:inputs.offset + inputs.limit]

        return build_api_response(
            data=dict(
                total=total,
                limit=inputs.limit,
                offset=inputs.offset,
                cases=[serialize_case(case) for case in page],
            ),
        )

    @action(
        detail=True,
        methods=[HTTPMethod.PATCH],
        url_path=r"cases/(?P<case_id>[^/.]+)",
    )
    def case(self, request, pk, case_id=None):
        inputs, errors = parse_case_inputs(pk, case_id, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        reviewer = self.reviewer(request)

        case = inputs.case.resolve(
            status=inputs.status,
            note=inputs.note,
            assignee=reviewer,
        )

        if inputs.note:
            CaseNote.objects.create(case=case, body=inputs.note, author=reviewer)

        return build_api_response(data=dict(case=serialize_case(case)))

    @action(
        detail=True,
        methods=[HTTPMethod.POST],
        url_path=r"simulations",
    )
    def simulations(self, request, pk):
        inputs, errors = parse_simulation_inputs(pk, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        return build_api_response(
            data=SimulatePolicy.call(
                application=inputs.application,
                weights=inputs.weights,
                thresholds=inputs.thresholds,
                days=inputs.days,
            ),
        )

    @staticmethod
    def reviewer(request):
        """The person resolving a case, if a person did: HMAC authenticates
        an application, and then there is no user to attribute it to."""
        user = getattr(request, "user", None)

        return user if getattr(user, "is_authenticated", False) else None
