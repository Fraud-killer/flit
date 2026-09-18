from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from api.base import build_api_response
from api.parsers import parse_collect_inputs
from core.services.collect_visit import CollectVisit


class CollectView(APIView):
    """
    Public endpoint the FLIT browser SDK posts device signals to.

    The collection key identifies an application; it does not authorise
    anything, so it is safe to embed in a page. Browsers call this directly,
    which is why it is CORS-open, unauthenticated and rate limited.
    """

    authentication_classes = []
    permission_classes = [AllowAny]

    CORS_HEADERS = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",
    }

    def options(self, request, *args, **kwargs):
        return build_api_response(data=None, headers=self.CORS_HEADERS)

    def post(self, request):
        inputs, errors = parse_collect_inputs(request)

        if errors:
            return build_api_response(errors=errors, headers=self.CORS_HEADERS)

        visit_token, identity, visit = CollectVisit.call(
            application=inputs.application,
            signals=inputs.signals,
            device_key=inputs.device_key,
            ip_address=self.client_ip(request),
        )

        return build_api_response(
            headers=self.CORS_HEADERS,
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
