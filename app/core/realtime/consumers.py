"""
The alert stream, one tenant at a time.

A websocket client sees the alerts of the applications it has proved it may
see, and nothing else. Proof is the application's secret key, or a signed-in
user who owns the organization. There is no shared channel a client lands on
by connecting: an alert about one merchant's customer is that merchant's
data, and a stream every connection could read would hand every tenant's
decisions to anyone who found the URL.
"""

import hmac
import logging
from typing import Optional

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from core.models import Application, Organization
from core.realtime.alerts import AlertManager


logger = logging.getLogger(__name__)


class AlertConsumer(AsyncJsonWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.application_id: Optional[str] = None
        self.organization_id: Optional[str] = None
        self.subscribed_channels: list = []

    async def connect(self):
        await self.accept()

        # Staff see the firehose; everyone else subscribes to what they own.
        if self.is_staff:
            await self.subscribe_to_channel(AlertManager.get_channel_name())

        await self.send_json({
            "type": "connection.established",
            "message": "Connected to alert stream",
        })

    async def disconnect(self, close_code):
        for channel in self.subscribed_channels:
            await self.channel_layer.group_discard(channel, self.channel_name)

        self.subscribed_channels.clear()

    async def receive_json(self, content):
        message_type = content.get("type")

        if message_type == "subscribe.application":
            await self.handle_subscribe_application(content)
        elif message_type == "subscribe.organization":
            await self.handle_subscribe_organization(content)
        elif message_type == "unsubscribe":
            await self.handle_unsubscribe(content)
        elif message_type == "acknowledge":
            await self.handle_acknowledge(content)
        elif message_type == "ping":
            await self.send_json({"type": "pong"})
        else:
            await self.send_json({
                "type": "error",
                "message": f"Unknown message type: {message_type}",
            })

    async def handle_subscribe_application(self, content):
        application_id = content.get("application_id")
        api_key = content.get("api_key")

        if not application_id:
            await self.send_json({
                "type": "error",
                "message": "application_id is required",
            })
            return

        is_valid = await self.validate_application_access(application_id, api_key)
        if not is_valid:
            await self.send_json({
                "type": "error",
                "message": "Invalid application credentials",
            })
            return

        channel = AlertManager.get_channel_name(application_id)
        await self.subscribe_to_channel(channel)
        self.application_id = application_id

        await self.send_json({
            "type": "subscription.confirmed",
            "channel": f"application:{application_id}",
        })

    async def handle_subscribe_organization(self, content):
        organization_id = content.get("organization_id")

        if not organization_id:
            await self.send_json({
                "type": "error",
                "message": "organization_id is required",
            })
            return

        is_valid = await self.validate_organization_access(organization_id)
        if not is_valid:
            await self.send_json({
                "type": "error",
                "message": "Not authorised for this organization",
            })
            return

        channel = AlertManager.get_organization_channel(organization_id)
        await self.subscribe_to_channel(channel)
        self.organization_id = organization_id

        await self.send_json({
            "type": "subscription.confirmed",
            "channel": f"organization:{organization_id}",
        })

    async def handle_unsubscribe(self, content):
        channel = content.get("channel")

        if channel and channel in self.subscribed_channels:
            await self.channel_layer.group_discard(channel, self.channel_name)
            self.subscribed_channels.remove(channel)

            await self.send_json({
                "type": "subscription.removed",
                "channel": channel,
            })

    async def handle_acknowledge(self, content):
        alert_id = content.get("alert_id")
        user_id = content.get("user_id")

        if not alert_id:
            await self.send_json({
                "type": "error",
                "message": "alert_id is required",
            })
            return

        await self.send_json({
            "type": "alert.acknowledged",
            "alert_id": alert_id,
            "acknowledged_by": user_id,
        })

    async def subscribe_to_channel(self, channel: str):
        if channel not in self.subscribed_channels:
            await self.channel_layer.group_add(channel, self.channel_name)
            self.subscribed_channels.append(channel)

    async def alert_message(self, event):
        alert = event.get("alert", {})

        await self.send_json({
            "type": "alert",
            "alert": alert,
        })

    # -- Who is on the other end -------------------------------------------

    @property
    def user(self):
        """The signed-in user, if the ASGI auth stack found a session."""
        user = self.scope.get("user")
        return user if user is not None and getattr(user, "is_authenticated", False) else None

    @property
    def is_staff(self):
        user = self.user
        return bool(user and getattr(user, "is_staff", False))

    @database_sync_to_async
    def validate_application_access(self, application_id: str, api_key: Optional[str]) -> bool:
        """
        The application's secret key, or a signed-in owner of its
        organization. Nothing else: an application id is not a secret, it is
        in every request path.
        """
        try:
            application = Application.objects.filter(id=application_id).first()
            if not application:
                return False

            if api_key:
                expected = application.raw_secret_key or ""
                return hmac.compare_digest(str(expected), str(api_key))

            return self._owns(application.organization)
        except Exception as e:
            logger.error(f"Error validating application access: {e}")
            return False

    @database_sync_to_async
    def validate_organization_access(self, organization_id: str) -> bool:
        try:
            organization = Organization.objects.filter(id=organization_id).first()
            if not organization:
                return False

            return self._owns(organization)
        except Exception as e:
            logger.error(f"Error validating organization access: {e}")
            return False

    def _owns(self, organization) -> bool:
        user = self.user
        if not user:
            return False
        return self.is_staff or organization.owner_id == user.id
