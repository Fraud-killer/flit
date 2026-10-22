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
from core.services.describe_account import DescribeAccount
from api.parsers import parse_account_lookup_inputs
from core.services.simulate_policy import SimulatePolicy
from api.parsers import parse_decision_filters, parse_case_inputs, parse_simulation_inputs
from api.parsers import parse_challenge_inputs, parse_challenge_verification
from api.parsers import parse_calibration_inputs
from api.serializers.case_serializers import serialize_case
from api.serializers.challenge_serializers import serialize_challenge
from core.services.publish_outcome import PublishOutcome
from core.services.challenges import ChallengeError, IssueChallenge, VerifyChallenge
from core.messages.challenges import msg_challenge_unavailable
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

        # A reported outcome is ground truth. Publishing it is what lets the
        # rest of the network learn from this merchant's experience.
        PublishOutcome.call(audit_log=audit_log, application=inputs.application)

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
        methods=[HTTPMethod.POST],
        url_path=r"challenges",
    )
    def challenges(self, request, pk):
        """
        Issue a step-up challenge for an actor a decision asked to verify.

        For an OTP the code comes back exactly once, in this response, and
        FLIT keeps only its digest. Delivering it is the merchant's job: they
        own the channel to their user and the relationship that makes a
        message from them trustworthy.
        """
        inputs, errors = parse_challenge_inputs(pk, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        challenge, code = IssueChallenge.call(
            application=inputs.application,
            client_id=inputs.client_id,
            method=inputs.method,
            audit_log=inputs.audit_log,
            identity_key_ids=inputs.identity_key_ids,
        )

        return build_api_response(
            data=dict(challenge=serialize_challenge(challenge, code=code)),
        )

    @action(
        detail=True,
        methods=[HTTPMethod.POST],
        url_path=r"challenges/(?P<challenge_id>[^/.]+)/verify",
    )
    def verify_challenge(self, request, pk, challenge_id=None):
        inputs, errors = parse_challenge_verification(pk, challenge_id, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        try:
            challenge, passed, reason = async_to_sync(VerifyChallenge.call)(
                challenge=inputs.challenge,
                response=inputs.response,
                remote_ip=inputs.remote_ip,
            )
        except ChallengeError as error:
            return build_api_response(
                errors=[msg_challenge_unavailable.new(
                    path="response", context=dict(detail=str(error)),
                )],
            )

        return build_api_response(
            data=dict(
                passed=passed,
                reason=reason,
                challenge=serialize_challenge(challenge),
            ),
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
        methods=[HTTPMethod.GET, HTTPMethod.POST],
        url_path=r"calibrations",
    )
    def calibrations(self, request, pk):
        """
        GET: the review queue — every calibration run, newest first, with
        what it proposed, accepted, rejected and why.
        POST: run the calibrator now. A dry run unless the body carries
        `apply: true`, and even then only proposals that pass the guardrails
        are written.
        """
        from core.models import CalibrationRun
        from core.calibration import Calibrator, serialize_run

        inputs, errors = parse_calibration_inputs(pk, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        if request.method == HTTPMethod.GET:
            runs = CalibrationRun.objects.filter(application=inputs.application)[:20]
            return build_api_response(data=dict(
                calibration=inputs.application.policy.calibration or {},
                runs=[serialize_run(run) for run in runs],
            ))

        run = Calibrator.run(
            application=inputs.application, days=inputs.days, apply=inputs.apply,
        )
        return build_api_response(data=serialize_run(run))

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

    @action(
        detail=True,
        methods=[HTTPMethod.GET],
        url_path=r"accounts/(?P<client_id>[^/.]+)",
    )
    def account(self, request, pk, client_id=None):
        inputs, errors = parse_account_lookup_inputs(pk, client_id)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, inputs.application).can_manage()

        account = DescribeAccount.call(
            application=inputs.application,
            client_id=inputs.client_id,
        )

        return build_api_response(data=dict(account=account))

    @staticmethod
    def reviewer(request):
        """The person resolving a case, if a person did: HMAC authenticates
        an application, and then there is no user to attribute it to."""
        user = getattr(request, "user", None)

        return user if getattr(user, "is_authenticated", False) else None
