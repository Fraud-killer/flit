from http import HTTPMethod
from api.base import build_api_response
from api.parsers import parse_audit_action
from rest_framework.viewsets import ViewSet
from rest_framework.decorators import action
from api.marshals import SetDeviceSdkKeyMarshal


class ApplicationViewSet(ViewSet):
    @action(detail=True, methods=[HTTPMethod.POST])
    def audit(self, request, pk):
        data, errors = parse_audit_action(pk, request)
        if errors: return build_api_response(errors=errors)

        ApplicationGuard(request.auth, data.application).can_manage()

        inputs, errors = marshal.parse_inputs()
        

        marshal.ensure_access(inputs)

        return build_api_response(data=marshal.audit(inputs))



    @action(detail=True, methods=[HTTPMethod.PATCH])
    def device_sdk_key(self, request, pk):
        marshal = SetDeviceSdkKeyMarshal(id=pk, request=request)

        inputs, errors = marshal.parse_inputs()
        if errors: return build_api_response(errors=errors)

        marshal.ensure_access(inputs)

        token, errors = marshal.set_device_sdk_key(inputs)
        if errors: return build_api_response(errors=errors)

        return build_api_response(data=dict(device_sdk_key_token=token))
