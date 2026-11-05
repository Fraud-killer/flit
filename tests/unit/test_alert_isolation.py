"""
One merchant's alerts are one merchant's data.

Before this, every websocket client was placed on a shared channel the
moment it connected, and every alert was published there; an application
subscription with no credentials was accepted; an organization subscription
was never checked at all. Anyone who found the URL could read every tenant's
fraud decisions as they happened.

Now a client sees nothing it has not proved it may see: the application's
secret key, or a signed-in owner of the organization.
"""

import asyncio

import pytest
from channels.testing import WebsocketCommunicator
from django.contrib.auth.models import AnonymousUser

from core.realtime.alerts import Alert, AlertManager
from core.realtime.consumers import AlertConsumer


def connect(user=None):
    communicator = WebsocketCommunicator(AlertConsumer.as_asgi(), "/ws/alerts/")
    communicator.scope["user"] = user or AnonymousUser()
    return communicator


async def open_stream(user=None):
    communicator = connect(user)
    connected, _ = await communicator.connect()
    assert connected
    established = await communicator.receive_json_from()
    assert established["type"] == "connection.established"
    return communicator


def alert_for(application):
    return Alert(
        title="High Risk Activity Detected",
        message="BLOCK",
        application_id=str(application.id),
        organization_id=str(application.organization_id),
    )


async def nothing_arrives(communicator):
    return await communicator.receive_nothing(timeout=0.2)


def secret_for(application):
    from core import mcrypt

    application.secret_key = mcrypt.encrypt("s3cret-" + str(application.id))
    application.save(update_fields=["secret_key"])
    return "s3cret-" + str(application.id)


class TestConnectingAlone:
    def test_a_fresh_connection_receives_no_alerts(self, application):
        async def run():
            stream = await open_stream()
            await AlertManager.send_alert(alert_for(application))
            quiet = await nothing_arrives(stream)
            await stream.disconnect()
            return quiet

        assert asyncio.run(run()) is True


class TestApplicationSubscription:
    def test_requires_the_secret_key(self, application):
        async def run():
            stream = await open_stream()
            await stream.send_json_to({
                "type": "subscribe.application",
                "application_id": str(application.id),
            })
            reply = await stream.receive_json_from()
            await AlertManager.send_alert(alert_for(application))
            quiet = await nothing_arrives(stream)
            await stream.disconnect()
            return reply, quiet

        reply, quiet = asyncio.run(run())
        assert reply["type"] == "error"
        assert quiet is True

    def test_a_wrong_key_is_refused(self, application):
        secret_for(application)

        async def run():
            stream = await open_stream()
            await stream.send_json_to({
                "type": "subscribe.application",
                "application_id": str(application.id),
                "api_key": "not-the-key",
            })
            reply = await stream.receive_json_from()
            await stream.disconnect()
            return reply

        assert asyncio.run(run())["type"] == "error"

    def test_the_right_key_receives_that_applications_alerts(self, application):
        key = secret_for(application)

        async def run():
            stream = await open_stream()
            await stream.send_json_to({
                "type": "subscribe.application",
                "application_id": str(application.id),
                "api_key": key,
            })
            confirmed = await stream.receive_json_from()
            await AlertManager.send_alert(alert_for(application))
            received = await stream.receive_json_from()
            await stream.disconnect()
            return confirmed, received

        confirmed, received = asyncio.run(run())
        assert confirmed["type"] == "subscription.confirmed"
        assert received["type"] == "alert"
        assert received["alert"]["application_id"] == str(application.id)

    def test_but_not_another_merchants(self, application, second_application):
        key = secret_for(application)

        async def run():
            stream = await open_stream()
            await stream.send_json_to({
                "type": "subscribe.application",
                "application_id": str(application.id),
                "api_key": key,
            })
            await stream.receive_json_from()
            await AlertManager.send_alert(alert_for(second_application))
            quiet = await nothing_arrives(stream)
            await stream.disconnect()
            return quiet

        assert asyncio.run(run()) is True

    def test_a_signed_in_owner_needs_no_key(self, application):
        async def run():
            stream = await open_stream(application.organization.owner)
            await stream.send_json_to({
                "type": "subscribe.application",
                "application_id": str(application.id),
            })
            reply = await stream.receive_json_from()
            await stream.disconnect()
            return reply

        assert asyncio.run(run())["type"] == "subscription.confirmed"

    def test_a_signed_in_stranger_is_refused(self, application, second_application):
        async def run():
            stream = await open_stream(second_application.organization.owner)
            await stream.send_json_to({
                "type": "subscribe.application",
                "application_id": str(application.id),
            })
            reply = await stream.receive_json_from()
            await stream.disconnect()
            return reply

        assert asyncio.run(run())["type"] == "error"


class TestOrganizationSubscription:
    def test_anonymous_is_refused(self, application):
        async def run():
            stream = await open_stream()
            await stream.send_json_to({
                "type": "subscribe.organization",
                "organization_id": str(application.organization_id),
            })
            reply = await stream.receive_json_from()
            await AlertManager.send_alert(alert_for(application))
            quiet = await nothing_arrives(stream)
            await stream.disconnect()
            return reply, quiet

        reply, quiet = asyncio.run(run())
        assert reply["type"] == "error"
        assert quiet is True

    def test_the_owner_receives_the_organizations_alerts(self, application):
        async def run():
            stream = await open_stream(application.organization.owner)
            await stream.send_json_to({
                "type": "subscribe.organization",
                "organization_id": str(application.organization_id),
            })
            confirmed = await stream.receive_json_from()
            await AlertManager.send_alert(alert_for(application))
            received = await stream.receive_json_from()
            await stream.disconnect()
            return confirmed, received

        confirmed, received = asyncio.run(run())
        assert confirmed["type"] == "subscription.confirmed"
        assert received["type"] == "alert"

    def test_another_owner_is_refused(self, application, second_application):
        async def run():
            stream = await open_stream(second_application.organization.owner)
            await stream.send_json_to({
                "type": "subscribe.organization",
                "organization_id": str(application.organization_id),
            })
            reply = await stream.receive_json_from()
            await stream.disconnect()
            return reply

        assert asyncio.run(run())["type"] == "error"


class TestAlertsCarryTheirTenant:
    def test_risk_alerts_name_the_organization(self, application, no_geoip):
        """
        Routing by organization only works if the alert says which one. The
        auditor used to leave it blank.
        """
        from unittest.mock import AsyncMock, patch

        from core.audit.auditor import Auditor
        from core.audit.events import RegistrationEvent
        from tests.unit.test_signup_defence import CURL

        sent = []

        async def capture(alert):
            sent.append(alert)

        event = RegistrationEvent(
            id="alert_1", client_id="alert_1", email="bot@example.com",
            country="US", ip_address="193.200.229.243", user_agent=CURL,
            action="registration",
        )

        with patch(
            "core.services.fingerprint.FetchVisitData.async_call",
            AsyncMock(return_value=None),
        ), patch.object(AlertManager, "send_alert", AsyncMock(side_effect=capture)):
            asyncio.run(Auditor.audit(event, application.policy, send_alerts=True))

        assert sent, "a bot signup from a reserved domain should raise an alert"
        assert sent[0].organization_id == str(application.organization_id)
        assert sent[0].application_id == str(application.id)
