from core.models import DeviceLocation
from rest_framework.serializers import ModelSerializer


class DeviceLocationSerializer(ModelSerializer):
    class Meta:
        model = DeviceLocation
        fields = [
            "id",
            "city",
            "state",
            "country",
            "latitude",
            "longitude",
            "created_at",
            "updated_at",
        ]
