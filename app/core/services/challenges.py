"""
Step-up challenges: issuing them, verifying them, and learning from them.

A challenge is how FLIT acts on evidence that is real but thin. Blocking on
thin evidence turns away real customers; allowing on it is what the attacker
is counting on. A challenge does neither — it raises the price of the action
until automating it stops paying, and leaves the honest user with one puzzle.

The outcome is fed straight back into the identity graph. An actor who fails
or abandons a challenge is more suspicious than one who was never asked, and
the next decision about that key knows it.
"""

import logging
from datetime import timedelta

import aiohttp
from asgiref.sync import sync_to_async
from django.utils import timezone

from core.models.challenge import Challenge, ChallengeMethod, ChallengeStatus
from core.services.network_reputation import NetworkReputation


logger = logging.getLogger(__name__)


TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_TIMEOUT_SECONDS = 5


class ChallengeError(Exception):
    pass


class IssueChallenge:
    """
    Create a challenge for an actor a decision asked to step up.

    For OTP, the code is returned exactly once, here, and only the digest is
    stored. FLIT does not deliver it: the merchant already owns the channel
    to their user and the relationship that makes a message from them
    trustworthy, and putting FLIT in that path would mean handing us contact
    details we have no reason to hold.
    """

    @classmethod
    def call(cls, *, application, client_id, method=ChallengeMethod.TURNSTILE,
             audit_log=None, identity_key_ids=None, ttl_seconds=None,
             max_attempts=None):
        if method not in ChallengeMethod.VALUES:
            raise ChallengeError(f"Unknown challenge method: {method}")

        ttl = ttl_seconds or Challenge.DEFAULT_TTL_SECONDS
        code = Challenge.generate_code() if method == ChallengeMethod.OTP else None

        challenge = Challenge.objects.create(
            application=application,
            client_id=client_id,
            method=method,
            audit_log=audit_log,
            # Stringified: this is a JSON column, and a UUID is not JSON.
            identity_key_ids=[str(value) for value in (identity_key_ids or [])],
            secret_hash=Challenge.hash_code(code) if code else "",
            max_attempts=max_attempts or Challenge.DEFAULT_MAX_ATTEMPTS,
            expires_at=timezone.now() + timedelta(seconds=ttl),
        )

        return challenge, code

    @classmethod
    async def call_async(cls, **kwargs):
        return await sync_to_async(cls.call)(**kwargs)


class TurnstileVerifier:
    """Checks a Turnstile token with Cloudflare."""

    @classmethod
    async def verify(cls, *, application, response, remote_ip=None):
        secret = application.raw_turnstile_secret

        if not secret:
            raise ChallengeError(
                "No Turnstile secret configured for this application",
            )

        payload = {"secret": secret, "response": response}
        if remote_ip:
            payload["remoteip"] = remote_ip

        timeout = aiohttp.ClientTimeout(total=TURNSTILE_TIMEOUT_SECONDS)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(TURNSTILE_VERIFY_URL, data=payload) as reply:
                    body = await reply.json()
        except Exception as error:
            # A verifier that cannot be reached must not silently pass the
            # actor. Failing closed on a challenge only costs a retry.
            logger.warning(f"Turnstile verification unreachable: {error}")
            raise ChallengeError("Could not reach the challenge verifier")

        return bool(body.get("success")), body.get("error-codes") or []


class VerifyChallenge:
    """
    Check an actor's answer, and record what it means.

    Every terminal outcome is written to the identity graph: a pass is
    evidence for the key, a failure or an exhausted set of attempts is
    evidence against it.
    """

    @classmethod
    async def call(cls, *, challenge, response, remote_ip=None):
        if challenge.status != ChallengeStatus.PENDING:
            return challenge, False, "already_resolved"

        if challenge.is_expired:
            await cls._resolve(challenge, ChallengeStatus.EXPIRED, "challenge_failed")
            return challenge, False, "expired"

        if challenge.attempts_remaining <= 0:
            await cls._resolve(challenge, ChallengeStatus.FAILED, "challenge_failed")
            return challenge, False, "no_attempts_remaining"

        await sync_to_async(cls._count_attempt)(challenge)

        if challenge.method == ChallengeMethod.OTP:
            passed = challenge.matches(response)
            reason = None if passed else "incorrect_code"
        else:
            passed, errors = await TurnstileVerifier.verify(
                application=challenge.application,
                response=response,
                remote_ip=remote_ip,
            )
            reason = None if passed else ",".join(errors) or "rejected"

        if passed:
            await cls._resolve(challenge, ChallengeStatus.PASSED, "challenge_passed")
            return challenge, True, None

        # Only the last attempt is a failure. Before that the actor may still
        # clear it, and recording a failure per keystroke would let a
        # fat-fingered customer look like an attack.
        if challenge.attempts_remaining <= 0:
            await cls._resolve(challenge, ChallengeStatus.FAILED, "challenge_failed")

        return challenge, False, reason

    @staticmethod
    def _count_attempt(challenge):
        challenge.attempts += 1
        challenge.save(update_fields=["attempts"])

    @classmethod
    async def _resolve(cls, challenge, status, outcome):
        await sync_to_async(cls._save_resolution)(challenge, status)

        if challenge.identity_key_ids:
            await NetworkReputation.record_async(
                identity_key_ids=challenge.identity_key_ids,
                application=challenge.application,
                outcome=outcome,
            )

    @staticmethod
    def _save_resolution(challenge, status):
        challenge.status = status
        challenge.resolved_at = timezone.now()
        challenge.save(update_fields=["status", "resolved_at"])


class ExpireChallenges:
    """
    Close out challenges nobody came back to.

    Abandonment is the most common outcome of a challenge that worked: the
    script simply moves on. Recording it is what turns a challenge from a
    speed bump into a signal.
    """

    @classmethod
    def call(cls, *, application=None, limit=500):
        queryset = Challenge.objects.filter(
            status=ChallengeStatus.PENDING, expires_at__lt=timezone.now(),
        )

        if application is not None:
            queryset = queryset.filter(application=application)

        expired = 0

        for challenge in queryset.select_related("application")[:limit]:
            challenge.status = ChallengeStatus.EXPIRED
            challenge.resolved_at = timezone.now()
            challenge.save(update_fields=["status", "resolved_at"])

            if challenge.identity_key_ids:
                NetworkReputation.record(
                    identity_key_ids=challenge.identity_key_ids,
                    application=challenge.application,
                    outcome="challenge_failed",
                )

            expired += 1

        return expired
