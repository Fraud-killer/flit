from django.urls import path, include
from rest_framework.routers import SimpleRouter

from . import views


router = SimpleRouter()

# Accept both /applications/{id}/audit-transaction and .../audit-transaction/.
# Without this the documented (slash-less) form 301s, and a redirected POST
# arrives with no body.
router.trailing_slash = "/?"

router.register("applications", views.ApplicationViewSet, basename="applications")

version_one_routes = [
    path("collect", views.CollectView.as_view(), name="collect"),
    path("", include(router.urls)),
]

urlpatterns = [path("v1/", include(version_one_routes))]
