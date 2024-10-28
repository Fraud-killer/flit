from django.urls import path, include
from rest_framework.routers import SimpleRouter

from . import views


router = SimpleRouter()

router.register("devices", views.DeviceViewSet, basename="devices")
router.register("applications", views.ApplicationViewSet, basename="applications")


version_one_routes = [
    path("", include(router.urls)),
    path("audit/<str:audit_type>/", views.AuditView.as_view(), name="audit"),
]


urlpatterns = [path("v1/", include(version_one_routes))]
