from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from api.base import build_api_response
from api.parsers import parse_collect_inputs
from core.services.collect_visit import CollectVisit
from core.messages.applications import msg_origin_not_allowed
from core.services.collect_origin import cors_headers, is_origin_allowed


class CollectView(APIView):
    """
    Public endpoint the FLIT browser SDK posts device signals to.

    The collection key identifies an application; it does not authorise
    anything, so it is safe to embed in a page. Browsers call this directly,
    which is why it is CORS-open, unauthenticated and rate limited.

    Which sites may use a key is limited by the application's origin
    allowlist, checked on the POST. A preflight carries no body, and so no
    key, which is why it stays permissive: it only authorises the method and
    headers, and the POST response is what the browser actually gates on.
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    def options(self, request, *args, **kwargs):
        return build_api_response(
            data=None,
            headers=cors_headers(request.headers.get("Origin")),
        )

    def post(self, request):
        origin = request.headers.get("Origin")
        headers = cors_headers(origin)

        inputs, errors = parse_collect_inputs(request)

        if errors:
            return build_api_response(errors=errors, headers=headers)

        if not is_origin_allowed(inputs.application, origin):
            return build_api_response(
                errors=[msg_origin_not_allowed.new(path="key", context=dict(origin=origin))],
                status_code=status.HTTP_403_FORBIDDEN,
                # No CORS headers: the browser must not read this response.
                headers=None,
            )

        visit_token, identity, visit = CollectVisit.call(
            application=inputs.application,
            signals=inputs.signals,
            device_key=inputs.device_key,
            ip_address=self.client_ip(request),
        )

        return build_api_response(
            headers=headers,
            data=dict(
                visit_token=visit_token,
                # The browser stores this and returns it next time.
                device_key=identity.external_id,
                expires_in=CollectVisit.VISIT_TTL_SECONDS,
            ),
        )

    @staticmethod
    def client_ip(request):
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        return request.META.get("REMOTE_ADDR")
