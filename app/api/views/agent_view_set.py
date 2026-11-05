"""
Agent FLIT's console surface, mounted under /applications/{id}/ and
/organizations/{id}/.

Reads need the application key or the owner. Three things need a person:
approving or rejecting a write the agent asked about, confirming a memory,
and writing a playbook. An application key lives on a server; a leaked key
must not be able to approve the agent's own actions.
"""

from http import HTTPMethod

from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

from api.base import build_api_response
from api.permissions import HasAuthenticated
from api.parsers import (
    parse_agent_policy_inputs, parse_investigation_inputs, parse_investigation_ref, parse_step_decision_inputs,
    parse_memory_inputs, parse_memory_ref, parse_monitor_inputs, parse_monitor_ref, parse_playbook_inputs,
)
from api.parsers.parse_decision_filters import parse_integer
from api.serializers.agent_serializers import serialize_investigation, serialize_step, serialize_memory, serialize_monitor
from core.guards import ApplicationGuard, OrganizationGuard
from core.messages.agent import (
    msg_agent_disabled, msg_agent_loosening, msg_person_required, msg_playbook_invalid, msg_investigation_state,
)
from core.models import AgentPolicy, InvestigationStatus, MonitorStatus, Playbook
from core.services.agent_policy_change import AgentPolicyChange, AgentPolicyLooseningForbidden


def person(request):
    user = getattr(request, "user", None)
    return user if getattr(user, "is_authenticated", False) else None


def need_person(request):
    if person(request) is None:
        return build_api_response(errors=[msg_person_required], status_code=403)
    return None


class ApplicationAgentViewSet(ViewSet):
    permission_classes = [HasAuthenticated]

    # -- policy ---------------------------------------------------------------------

    @action(detail=True, methods=[HTTPMethod.GET, HTTPMethod.PATCH], url_path=r"agent-policy")
    def agent_policy(self, request, pk):
        inputs, errors = parse_agent_policy_inputs(pk, request)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, inputs.owner).can_manage()

        policy = AgentPolicy.for_application(inputs.owner)
        organization_policy = AgentPolicy.for_organization(inputs.owner.organization)

        if request.method == HTTPMethod.PATCH:
            try:
                AgentPolicyChange.apply(
                    policy=policy, changes=inputs.changes, actor=request.auth, organization=inputs.owner.organization,
                )
            except AgentPolicyLooseningForbidden as refusal:
                return build_api_response(
                    errors=[msg_agent_loosening.new(context=dict(loosened=refusal.loosened))], status_code=403,
                )

        return build_api_response(data=AgentPolicyChange.describe(policy, organization_policy=organization_policy))

    @action(detail=True, methods=[HTTPMethod.POST], url_path=r"agent-policy/reset-breaker")
    def reset_breaker(self, request, pk):
        from core.agent import AgentGuardrails
        inputs, errors = parse_agent_policy_inputs(pk, request)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, inputs.owner).can_manage()
        refused = need_person(request)
        if refused: return refused
        AgentGuardrails.reset(inputs.owner)
        return build_api_response(data=dict(reset=True))

    # -- investigations -------------------------------------------------------------

    @action(detail=True, methods=[HTTPMethod.GET, HTTPMethod.POST], url_path=r"investigations")
    def investigations(self, request, pk):
        from core.agent import Investigations, AgentGuardrails, PlaybookError
        from core.models import Investigation

        inputs, errors = parse_investigation_inputs(pk, request)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, inputs.application).can_manage()

        if request.method == HTTPMethod.POST:
            policy = AgentPolicy.for_application(inputs.application)
            reason = AgentGuardrails.disabled_reason(
                inputs.application, policy, AgentPolicy.for_organization(inputs.application.organization),
            )
            if reason:
                return build_api_response(errors=[msg_agent_disabled.new(context=dict(reason=reason))], status_code=409)
            try:
                investigation = Investigations.open(
                    application=inputs.application, playbook=inputs.playbook, subject=inputs.subject,
                    case=inputs.case, requested_by=person(request), mode=inputs.mode,
                )
            except PlaybookError as problem:
                return build_api_response(errors=[msg_playbook_invalid.new(context=dict(problem=str(problem)))])
            return build_api_response(data=dict(investigation=serialize_investigation(investigation)), status_code=202)

        status_filter = request.query_params.get("status")
        limit, _ = parse_integer(request.query_params.get("limit"), 25, 1, 100)
        offset, _ = parse_integer(request.query_params.get("offset"), 0, 0, 100000)
        queryset = Investigation.objects.filter(application=inputs.application).select_related("requested_by")
        if status_filter in InvestigationStatus.VALUES:
            queryset = queryset.filter(status=status_filter)
        elif status_filter == "open":
            queryset = queryset.filter(status__in=InvestigationStatus.OPEN)
        total = queryset.count()
        page = queryset.order_by("-created_at")[offset:offset + limit]
        return build_api_response(data=dict(
            total=total, limit=limit, offset=offset,
            investigations=[serialize_investigation(i) for i in page],
        ))

    @action(detail=True, methods=[HTTPMethod.GET, HTTPMethod.PATCH], url_path=r"investigations/(?P<investigation_id>[^/.]+)")
    def investigation(self, request, pk, investigation_id=None):
        from core.agent import Investigations

        errors = []
        application, investigation = parse_investigation_ref(pk, investigation_id, errors)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, application).can_manage()

        if request.method == HTTPMethod.PATCH:
            body = request.data if isinstance(request.data, dict) else {}
            if body.get("status") != InvestigationStatus.CANCELLED:
                return build_api_response(errors=[msg_investigation_state.new(context=dict(allowed=["cancelled"]))])
            try:
                Investigations.cancel(investigation, user=person(request))
            except ValueError as problem:
                return build_api_response(errors=[msg_investigation_state.new(context=dict(problem=str(problem)))], status_code=409)

        transcript = request.query_params.get("transcript") in ("1", "true", "yes")
        return build_api_response(data=dict(investigation=serialize_investigation(investigation, steps=True, transcript=transcript)))

    @action(
        detail=True, methods=[HTTPMethod.PATCH],
        url_path=r"investigations/(?P<investigation_id>[^/.]+)/steps/(?P<step_id>[^/.]+)",
    )
    def step(self, request, pk, investigation_id=None, step_id=None):
        """A person approves or rejects a write the agent asked about."""
        from core.agent import Investigations

        inputs, errors = parse_step_decision_inputs(pk, investigation_id, step_id, request)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, inputs.application).can_manage()
        refused = need_person(request)
        if refused: return refused

        try:
            Investigations.answer(inputs.step, user=person(request), note=inputs.note, approved=inputs.approved)
        except ValueError as problem:
            return build_api_response(errors=[msg_investigation_state.new(context=dict(problem=str(problem)))], status_code=409)

        inputs.step.refresh_from_db()
        inputs.investigation.refresh_from_db()
        return build_api_response(data=dict(
            step=serialize_step(inputs.step), investigation=serialize_investigation(inputs.investigation),
        ))

    # -- memories -------------------------------------------------------------------

    @action(detail=True, methods=[HTTPMethod.GET, HTTPMethod.POST], url_path=r"memories")
    def memories(self, request, pk):
        from core.agent import Memory

        if request.method == HTTPMethod.POST:
            inputs, errors = parse_memory_inputs(pk, request)
            if errors: return build_api_response(errors=errors)
            ApplicationGuard(request.auth, inputs.application).can_manage()
            refused = need_person(request)
            if refused: return refused
            memory = Memory.save(
                organization=inputs.application.organization,
                application=inputs.application if inputs.application_only else None,
                kind=inputs.kind, name=inputs.name, description=inputs.description, body=inputs.body,
                tags=inputs.tags, refers_to=inputs.refers_to, created_by=person(request),
            )
            return build_api_response(data=dict(memory=serialize_memory(memory)), status_code=201)

        errors = []
        from api.parsers.parse_application_id import parse_application_id
        application = parse_application_id(pk, errors)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, application).can_manage()

        query = request.query_params.get("q")
        kind = request.query_params.get("kind")
        if query:
            memories = Memory.recall(organization=application.organization, application=application, query=query, kind=kind or None, limit=25)
        else:
            memories = Memory.visible(organization=application.organization, application=application)
            if kind:
                memories = memories.filter(kind=kind)
            memories = list(memories.order_by("-updated_at")[:100])
        return build_api_response(data=dict(
            memories=[serialize_memory(m) for m in memories],
            index=Memory.index(organization=application.organization, application=application),
        ))

    @action(detail=True, methods=[HTTPMethod.PATCH, HTTPMethod.DELETE], url_path=r"memories/(?P<memory_id>[^/.]+)")
    def memory(self, request, pk, memory_id=None):
        from core.agent import Memory

        errors = []
        application, memory = parse_memory_ref(pk, memory_id, errors)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, application).can_manage()
        refused = need_person(request)
        if refused: return refused

        if request.method == HTTPMethod.DELETE:
            Memory.forget(memory)
            return build_api_response(data=dict(forgotten=True))

        body = request.data if isinstance(request.data, dict) else {}
        if body.get("confirmed") is True:
            Memory.confirm(memory, person(request))
        if isinstance(body.get("body"), str) and body["body"].strip():
            memory.body = body["body"][:4000]
            memory.save(update_fields=["body", "updated_at"])
        memory.refresh_from_db()
        return build_api_response(data=dict(memory=serialize_memory(memory)))

    # -- monitors -------------------------------------------------------------------

    @action(detail=True, methods=[HTTPMethod.GET, HTTPMethod.POST], url_path=r"monitors")
    def monitors(self, request, pk):
        from datetime import timedelta
        from django.utils import timezone
        from core.models import Monitor

        if request.method == HTTPMethod.POST:
            inputs, errors = parse_monitor_inputs(pk, request)
            if errors: return build_api_response(errors=errors)
            ApplicationGuard(request.auth, inputs.application).can_manage()
            monitor = Monitor.objects.create(
                application=inputs.application, name=inputs.name, subject=inputs.subject, metric=inputs.metric,
                factor=inputs.factor, threshold=inputs.threshold, window_minutes=inputs.window_minutes,
                action=inputs.action, playbook=inputs.playbook,
                expires_at=timezone.now() + timedelta(hours=inputs.expires_hours), created_by=person(request),
            )
            return build_api_response(data=dict(monitor=serialize_monitor(monitor)), status_code=201)

        errors = []
        from api.parsers.parse_application_id import parse_application_id
        application = parse_application_id(pk, errors)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, application).can_manage()
        status_filter = request.query_params.get("status", MonitorStatus.ACTIVE)
        monitors = Monitor.objects.filter(application=application)
        if status_filter != "all":
            monitors = monitors.filter(status=status_filter)
        return build_api_response(data=dict(monitors=[serialize_monitor(m) for m in monitors.order_by("-created_at")[:200]]))

    @action(detail=True, methods=[HTTPMethod.DELETE], url_path=r"monitors/(?P<monitor_id>[^/.]+)")
    def monitor(self, request, pk, monitor_id=None):
        errors = []
        application, monitor = parse_monitor_ref(pk, monitor_id, errors)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, application).can_manage()
        if monitor.status == MonitorStatus.ACTIVE:
            monitor.status = MonitorStatus.CANCELLED
            monitor.save(update_fields=["status"])
        return build_api_response(data=dict(monitor=serialize_monitor(monitor)))

    # -- playbooks (read) -----------------------------------------------------------

    @action(detail=True, methods=[HTTPMethod.GET], url_path=r"playbooks")
    def playbooks(self, request, pk):
        from core.agent import Playbooks

        errors = []
        from api.parsers.parse_application_id import parse_application_id
        application = parse_application_id(pk, errors)
        if errors: return build_api_response(errors=errors)
        ApplicationGuard(request.auth, application).can_manage()
        policy = AgentPolicy.for_application(application)
        specs = Playbooks.available(application.organization)
        return build_api_response(data=dict(playbooks=[
            dict(spec.as_dict(), evaluation=(policy.evaluations or {}).get(name) or spec.evaluation)
            for name, spec in sorted(specs.items())
        ]))


class OrganizationAgentViewSet(ViewSet):
    permission_classes = [HasAuthenticated]

    @action(detail=True, methods=[HTTPMethod.GET, HTTPMethod.PATCH], url_path=r"agent-policy")
    def agent_policy(self, request, pk):
        """The ceiling over every application: mode, deny and ask rules, the switch. Owner only."""
        inputs, errors = parse_agent_policy_inputs(pk, request, scope="organization")
        if errors: return build_api_response(errors=errors)
        OrganizationGuard(request.auth, inputs.owner).can_manage()

        policy, _ = AgentPolicy.objects.get_or_create(organization=inputs.owner)
        if request.method == HTTPMethod.PATCH:
            changes = {k: v for k, v in inputs.changes.items() if k in ("enabled", "mode", "ask", "deny", "allow", "auto_rules")}
            AgentPolicyChange.apply(policy=policy, changes=changes, actor=request.auth, organization=inputs.owner)
        return build_api_response(data=AgentPolicyChange.describe(policy))

    @action(detail=True, methods=[HTTPMethod.GET, HTTPMethod.PUT], url_path=r"playbooks")
    def playbooks(self, request, pk):
        from core.agent import Playbooks, PlaybookError

        inputs, errors = parse_playbook_inputs(pk, request)
        if errors: return build_api_response(errors=errors)
        OrganizationGuard(request.auth, inputs.organization).can_manage()

        if request.method == HTTPMethod.PUT:
            try:
                row = Playbooks.save(organization=inputs.organization, text=inputs.text, created_by=person(request))
            except PlaybookError as problem:
                return build_api_response(errors=[msg_playbook_invalid.new(context=dict(problem=str(problem)))])
            return build_api_response(data=dict(playbook=Playbooks.render(Playbooks.resolve(row.name, inputs.organization))), status_code=201)

        specs = Playbooks.available(inputs.organization)
        return build_api_response(data=dict(playbooks=[Playbooks.render(spec) for _, spec in sorted(specs.items())]))

    @action(detail=True, methods=[HTTPMethod.DELETE], url_path=r"playbooks/(?P<name>[a-z0-9_-]+)")
    def playbook(self, request, pk, name=None):
        inputs, errors = parse_playbook_inputs(pk, request)
        if errors: return build_api_response(errors=errors)
        OrganizationGuard(request.auth, inputs.organization).can_manage()
        deleted, _ = Playbook.objects.filter(organization=inputs.organization, name=name).delete()
        return build_api_response(data=dict(deleted=bool(deleted)))
