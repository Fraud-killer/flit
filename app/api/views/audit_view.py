from api.marshals import AuditMarshal
from api.base import build_api_response
from rest_framework.views import APIView


class AuditView(APIView):
    def post(self, request, audit_type):
        marshal = AuditMarshal(request=request, audit_type=audit_type)

        inputs, errors = marshal.parse_inputs()
        if errors: return build_api_response(errors=errors)

        marshal.ensure_access(inputs)

        return build_api_response(data=marshal.audit(inputs))
