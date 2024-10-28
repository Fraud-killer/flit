from rest_framework import status
from api.base import build_api_response
from rest_framework.viewsets import ViewSet
from api.marshals import RegisterDeviceMarshal
from api.serializers.device_serializers import DeviceSerializer


class DeviceViewSet(ViewSet):
    def create(self, request):
        marshal = RegisterDeviceMarshal(request=request)

        inputs, errors = marshal.parse_inputs()
        if errors: return build_api_response(errors=errors)

        marshal.ensure_access(inputs)

        device, errors = marshal.register_device(inputs)
        if errors: return build_api_response(errors=errors)

        status_code = status.HTTP_201_CREATED
        data = dict(device=DeviceSerializer(device).data)

        return build_api_response(data=data, status_code=status_code)
