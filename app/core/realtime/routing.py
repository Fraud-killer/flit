from django.urls import path
from core.realtime.consumers import AlertConsumer


websocket_urlpatterns = [
    path("ws/alerts/", AlertConsumer.as_asgi()),
]
