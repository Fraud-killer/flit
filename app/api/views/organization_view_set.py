from http import HTTPMethod

from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

from api.base import build_api_response
from api.permissions import HasAuthenticated
from api.parsers.parse_organization_policy_inputs import parse_organization_policy_inputs
from core.guards import OrganizationGuard


class OrganizationViewSet(ViewSet):
    permission_classes = [HasAuthenticated]

    @action(
        detail=True,
        methods=[HTTPMethod.GET, HTTPMethod.PATCH],
        url_path=r"policy",
    )
    def policy(self, request, pk):
        """
        The organization's standing instructions: rules every application
        inherits, the threshold ceiling, required enforcement, rules switched
        off across the estate. Owner only; an application key cannot read or
        write its organization's policy.
        """
        from core.models import OrganizationPolicy
        from core.services.organization_policy_change import OrganizationPolicyChange

        inputs, errors = parse_organization_policy_inputs(pk, request)
        if errors: return build_api_response(errors=errors)

        OrganizationGuard(request.auth, inputs.organization).can_manage()

        policy, _ = OrganizationPolicy.objects.get_or_create(organization=inputs.organization)

        if request.method == HTTPMethod.PATCH:
            OrganizationPolicyChange.apply(policy=policy, changes=inputs.changes, actor=request.auth)

        return build_api_response(data=OrganizationPolicyChange.describe(policy))
