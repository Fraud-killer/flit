"""
Tests for the challenge endpoints.

A merchant's whole interaction with a step-up is two calls: ask FLIT for a
challenge, then hand back what the actor answered. These exercise that path
through the API rather than the services underneath it, because a decision
layer that cannot be driven over HTTP is not a decision layer anyone can use.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from tests.unit.test_challenges import turnstile_reply


def client_for(application):
    from rest_framework.test import APIClient
    from core.auth.actor import Actor

    client = APIClient()
    client.force_authenticate(user=None, token=Actor(application))
    return client


def issue(client, application, **payload):
    payload.setdefault("client_id", "actor_1")
    payload.setdefault("method", "otp")

    return client.post(
        f"/api/v1/applications/{application.id}/challenges", payload, format="json",
    )


def verify(client, application, challenge_id, **payload):
    return client.post(
        f"/api/v1/applications/{application.id}/challenges/{challenge_id}/verify",
        payload,
        format="json",
    )


def body(response):
    return response.json().get("data") or {}


class TestIssuingAChallenge:
    def test_returns_a_challenge_and_its_code_once(self, application):
        client = client_for(application)

        response = issue(client, application)
        challenge = body(response)["challenge"]

        assert response.status_code == 200
        assert challenge["method"] == "otp"
        assert challenge["status"] == "pending"
        assert len(challenge["code"]) == 6

    def test_a_turnstile_challenge_carries_no_code(self, application):
        client = client_for(application)

        challenge = body(issue(client, application, method="turnstile"))["challenge"]

        assert "code" not in challenge

    def test_rejects_an_unknown_method(self, application):
        client = client_for(application)

        response = issue(client, application, method="carrier-pigeon")

        assert response.status_code != 200
        assert "method" in str(response.json())

    def test_requires_a_client_id(self, application):
        client = client_for(application)

        response = client.post(
            f"/api/v1/applications/{application.id}/challenges",
            dict(method="otp"),
            format="json",
        )

        assert response.status_code != 200

    def test_another_merchant_cannot_issue_against_this_application(
        self, application, second_application,
    ):
        response = issue(client_for(second_application), application)

        assert response.status_code in (401, 403, 404)


class TestVerifyingAChallenge:
    def test_the_right_code_passes(self, application):
        client = client_for(application)
        challenge = body(issue(client, application))["challenge"]

        response = verify(
            client, application, challenge["id"], response=challenge["code"],
        )

        assert body(response)["passed"] is True
        assert body(response)["challenge"]["status"] == "passed"

    def test_the_wrong_code_does_not(self, application):
        client = client_for(application)
        challenge = body(issue(client, application))["challenge"]

        response = verify(client, application, challenge["id"], response="000000")

        assert body(response)["passed"] is False
        assert body(response)["reason"] == "incorrect_code"

    def test_a_turnstile_token_is_checked_with_cloudflare(self, application):
        from core import mcrypt

        application.turnstile_secret = mcrypt.encrypt("secret")
        application.save(update_fields=["turnstile_secret"])

        client = client_for(application)
        challenge = body(issue(client, application, method="turnstile"))["challenge"]

        with turnstile_reply({"success": True}):
            response = verify(client, application, challenge["id"], response="token")

        assert body(response)["passed"] is True

    def test_an_unreachable_verifier_is_an_error_not_a_pass(self, application):
        from core import mcrypt

        application.turnstile_secret = mcrypt.encrypt("secret")
        application.save(update_fields=["turnstile_secret"])

        client = client_for(application)
        challenge = body(issue(client, application, method="turnstile"))["challenge"]

        session = MagicMock()
        session.__aenter__ = AsyncMock(side_effect=OSError("network down"))
        session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", MagicMock(return_value=session)):
            response = verify(client, application, challenge["id"], response="token")

        assert body(response).get("passed") is not True
        assert "challenge_unavailable" in str(response.json())

    def test_a_challenge_from_another_merchant_is_not_found(
        self, application, second_application,
    ):
        challenge = body(issue(client_for(application), application))["challenge"]

        response = verify(
            client_for(second_application),
            second_application,
            challenge["id"],
            response="000000",
        )

        assert response.status_code != 200 or body(response).get("passed") is not True

    def test_requires_a_response(self, application):
        client = client_for(application)
        challenge = body(issue(client, application))["challenge"]

        response = client.post(
            f"/api/v1/applications/{application.id}/challenges/{challenge['id']}/verify",
            {},
            format="json",
        )

        assert response.status_code != 200


class TestAuditModes:
    """
    The signup-surface rules are only worth having if a merchant can reach
    them. RegistrationEvent existed and was tested for a while before it was
    routable, which made the whole surface unreachable over HTTP.
    """

    def audit(self, client, application, mode, payload):
        return client.post(
            f"/api/v1/applications/{application.id}/audit-{mode}",
            payload, format="json",
        )

    def test_a_registration_can_be_audited_over_the_api(self, application):
        response = self.audit(
            client_for(application), application, "registration",
            dict(
                id="signup_1",
                email="figopentest563d42fd@uberip.com",
                country="NG",
                ip_address="193.200.229.243",
                user_agent="curl/8.20.0",
            ),
        )

        assert response.status_code == 200
        assert "disposable_email_domain" in body(response)["factors"]

    def test_a_crypto_transfer_can_be_audited_over_the_api(self, application):
        response = self.audit(
            client_for(application), application, "transaction",
            dict(
                id="tx_1", type="debit", amount=100, currency_code="USD",
                client_id="user_1", chain="polygon", asset="USDC",
                counterparty_address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
            ),
        )

        assert response.status_code == 200

    def test_an_unknown_mode_lists_what_is_available(self, application):
        response = self.audit(
            client_for(application), application, "telepathy", dict(id="x"),
        )

        assert response.status_code != 200
        assert "registration" in str(response.json())
