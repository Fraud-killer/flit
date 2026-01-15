from django.contrib import admin
from django.urls import path, include
from core.health import health_check, readiness_check, liveness_check, detailed_status


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("api.urls")),
    
    # Health check endpoints
    path("health/", health_check, name="health"),
    path("health/ready/", readiness_check, name="readiness"),
    path("health/live/", liveness_check, name="liveness"),
    path("health/status/", detailed_status, name="status"),
]
