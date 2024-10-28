from uuid import uuid4
from django.db import models

from .device import Device


class DeviceLocation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    city = models.CharField(max_length=160)
    state = models.CharField(max_length=160)
    country = models.CharField(max_length=160)
    latitude = models.FloatField()
    longitude = models.FloatField()
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    device = models.ForeignKey(Device, related_name="locations", on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Device Location"
        verbose_name_plural = "Device Locations"

    def __str__(self):
        return f"Device Location ({self.longitude}, {self.latitude})"
