"""
Tests for step-up challenges.

A challenge is how FLIT acts on evidence that is real but thin. What makes it
worth issuing is not the puzzle — it is that the outcome is remembered, so an
actor who walks away from three of them is not treated as a stranger on the
fourth.
"""

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from django.utils import timezone

from tests.unit.test_signup_defence import BROWSER, codes, register


def issue(application, *, method="otp", client_id="actor_1", identity_key_ids=None):
    from core.services.challenges import IssueChallenge

    return IssueChallenge.call(
        application=application,
        client_id=client_id,
        method=method,
        identity_key_ids=identity_key_ids or [],
    )


def verify(challenge, response, remote_ip=None):
    from core.services.challenges import VerifyChallenge

    return asyncio.run(
        VerifyChallenge.call(
            challenge=challenge, response=response, remote_ip=remote_ip,
        )
    )


def turnstile_reply(body):
    """A stubbed Cloudflare siteverify response."""
    reply = MagicMock()
    reply.json = AsyncMock(return_value=body)

    post = MagicMock()
    post.__aenter__ = AsyncMock(return_value=reply)
    post.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.post = MagicMock(return_value=post)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)

    return patch("aiohttp.ClientSession", MagicMock(return_value=session))


class TestOneTimeCodes:
    def test_the_code_is_returned_once_and_never_stored(self, application):
        challenge, code = issue(application)

        assert code is not None and len(code) == 6
        # Only the digest is kept, so a database read cannot clear a challenge.
        assert code not in challenge.secret_hash
        assert challenge.secret_hash == challenge.hash_code(code)

    def test_the_right_code_passes(self, application):
        challenge, code = issue(application)

        challenge, passed, reason = verify(challenge, code)

        assert passed
        assert reason is None
        assert challenge.status == "passed"

    def test_the_wrong_code_does_not(self, application):
        challenge, code = issue(application)

        _, passed, reason = verify(challenge, "000000")

        assert not passed
        assert reason == "incorrect_code"

    def test_a_typo_is_not_treated_as_an_attack(self, application):
        """
        A customer gets to fumble. Only the last attempt is a failure — the
        alternative is that a fat-fingered user looks like a bot.
        """
        challenge, code = issue(application)

        challenge, _, _ = verify(challenge, "000000")

        assert challenge.status == "pending"
        assert challenge.attempts == 1

    def test_running_out_of_attempts_fails_the_challenge(self, application):
        challenge, code = issue(application)

        for _ in range(challenge.max_attempts):
            challenge, passed, _ = verify(challenge, "000000")

        assert not passed
        assert challenge.status == "failed"

    def test_an_expired_challenge_cannot_be_cleared(self, application):
        challenge, code = issue(application)
        challenge.expires_at = timezone.now() - timedelta(minutes=1)
        challenge.save(update_fields=["expires_at"])

        challenge, passed, reason = verify(challenge, code)

        assert not passed
        assert reason == "expired"
        assert challenge.status == "expired"

    def test_a_resolved_challenge_cannot_be_replayed(self, application):
        challenge, code = issue(application)
        verify(challenge, code)

        _, passed, reason = verify(challenge, code)

        assert not passed
        assert reason == "already_resolved"


class TestTurnstile:
    def with_secret(self, application):
        from core import mcrypt

        application.turnstile_secret = mcrypt.encrypt("test-turnstile-secret")
        application.save(update_fields=["turnstile_secret"])
        return application

    def test_the_secret_is_stored_encrypted(self, application):
        self.with_secret(application)
        application.refresh_from_db()

        assert "test-turnstile-secret" not in application.turnstile_secret
        assert application.raw_turnstile_secret == "test-turnstile-secret"

    def test_a_valid_token_passes(self, application):
        self.with_secret(application)
        challenge, _ = issue(application, method="turnstile")

        with turnstile_reply({"success": True}):
            challenge, passed, _ = verify(challenge, "token", remote_ip="1.2.3.4")

        assert passed
        assert challenge.status == "passed"

    def test_a_rejected_token_does_not(self, application):
        self.with_secret(application)
        challenge, _ = issue(application, method="turnstile")

        with turnstile_reply({"success": False, "error-codes": ["invalid-input-response"]}):
            _, passed, reason = verify(challenge, "token")

        assert not passed
        assert reason == "invalid-input-response"

    def test_an_unreachable_verifier_fails_closed(self, application):
        """
        A verifier that cannot be reached must not wave the actor through.
        Failing closed on a challenge costs a retry; failing open costs the
        whole control.
        """
        from core.services.challenges import ChallengeError

        self.with_secret(application)
        challenge, _ = issue(application, method="turnstile")

        session = MagicMock()
        session.__aenter__ = AsyncMock(side_effect=OSError("network down"))
        session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", MagicMock(return_value=session)):
            try:
                verify(challenge, "token")
                raise AssertionError("should have refused to pass the actor")
            except ChallengeError:
                pass

    def test_a_missing_secret_is_an_error_not_a_pass(self, application):
        from core.services.challenges import ChallengeError

        challenge, _ = issue(application, method="turnstile")

        with patch.object(
            type(application), "raw_turnstile_secret",
            property(lambda self: None),
        ):
            try:
                verify(challenge, "token")
                raise AssertionError("should have refused to pass the actor")
            except ChallengeError:
                pass


class TestTheLoopCloses:
    def key_ids(self, application, value="185.199.109.55"):
        from tests.unit.test_protection_network import key_for

        return [key_for("ip", value).id]

    def test_passing_a_challenge_is_recorded(self, application):
        keys = self.key_ids(application)
        challenge, code = issue(application, identity_key_ids=keys)

        verify(challenge, code)

        from core.models.identity import IdentityObservation

        observation = IdentityObservation.objects.get(
            identity_key_id=keys[0], application=application,
        )
        assert observation.challenge_passed_count == 1

    def test_failing_a_challenge_is_recorded(self, application):
        keys = self.key_ids(application)
        challenge, _ = issue(application, identity_key_ids=keys)

        for _ in range(challenge.max_attempts):
            challenge, _, _ = verify(challenge, "000000")

        from core.models.identity import IdentityObservation

        observation = IdentityObservation.objects.get(
            identity_key_id=keys[0], application=application,
        )
        assert observation.challenge_failed_count == 1

    def test_abandonment_is_recorded_too(self, application):
        """
        The most common outcome of a challenge that worked: the script simply
        moves on. If that is not remembered, the challenge taught us nothing.
        """
        from core.services.challenges import ExpireChallenges

        keys = self.key_ids(application)
        challenge, _ = issue(application, identity_key_ids=keys)
        challenge.expires_at = timezone.now() - timedelta(minutes=1)
        challenge.save(update_fields=["expires_at"])

        assert ExpireChallenges.call(application=application) == 1

        from core.models.identity import IdentityObservation

        observation = IdentityObservation.objects.get(
            identity_key_id=keys[0], application=application,
        )
        assert observation.challenge_failed_count == 1

    def test_an_actor_who_keeps_failing_is_flagged_next_time(
        self, application, no_geoip,
    ):
        from core.services.network_reputation import NetworkReputation

        ip = "185.199.109.77"
        keys = self.key_ids(application, ip)

        NetworkReputation.record(
            identity_key_ids=keys, application=application,
            outcome="challenge_failed", count=3,
        )

        result = register(
            application,
            email="persistent@gmail.com",
            ip_address=ip,
            user_agent=BROWSER,
            client_id="persistent_1",
        )

        assert "challenge_evasion" in codes(result)

    def test_one_failure_alone_does_not_flag_anyone(
        self, application, no_geoip,
    ):
        from core.services.network_reputation import NetworkReputation

        ip = "185.199.109.88"
        keys = self.key_ids(application, ip)

        NetworkReputation.record(
            identity_key_ids=keys, application=application,
            outcome="challenge_failed",
        )

        result = register(
            application,
            email="unlucky@gmail.com",
            ip_address=ip,
            user_agent=BROWSER,
            client_id="unlucky_1",
        )

        assert "challenge_evasion" not in codes(result)
