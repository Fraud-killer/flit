from core.models import Device
from rest_framework.serializers import ModelSerializer

from .device_location_serializers import DeviceLocationSerializer


class DeviceSerializer(ModelSerializer):
    locations = DeviceLocationSerializer(many=True, read_only=True)

    class Meta:
        model = Device
        fields = ["id", "fingerprint", "created_at", "updated_at", "locations"]
