from core.models import Device
from rest_framework.serializers import ModelSerializer


class DeviceSerializer(ModelSerializer):
    class Meta:
        model = Device
        fields = ["id", "client_id", "fingerprint", "locations", "created_at", "updated_at"]
