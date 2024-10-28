from core import models
from django.contrib import auth
from django.contrib import admin


admin.site.unregister(auth.models.Group)

admin.site.register(models.User)
admin.site.register(models.Device)
admin.site.register(models.Policy)
admin.site.register(models.Application)
admin.site.register(models.Organization)
admin.site.register(models.DeviceLocation)
