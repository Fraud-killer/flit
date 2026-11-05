"""
A cleared step-up buys something, and only so much.

The loop: FLIT says challenge, the merchant challenges, the user clears it,
the merchant asks again with the challenge id. The replay is checked (right
application, right account, recently cleared) and bounded (three replays, a
quarter of an hour), and the engine discounts the score and waives the
challenge — never a hard block.
"""

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from django.utils import timezone


def audit(application, event):
    from core.audit.auditor import Auditor

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=None),
    ):
        return asyncio.run(Auditor.audit(event, application.policy, send_alerts=False))


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"


def signup(application, *, client_id, challenge_id=None, user_agent=BROWSER):
    """A signup with thin evidence: a throwaway domain, nothing else. Challenge territory."""
    from core.audit.events import RegistrationEvent

    extra = dict(challenge_id=challenge_id) if challenge_id else {}
    return audit(application, RegistrationEvent(
        id=client_id, client_id=client_id, email=f"{client_id}@mailinator.com", country="US",
        ip_address="102.91.133.202", user_agent=user_agent, action="registration", **extra,
    ))


def passed_challenge(application, client_id="actor_1", minutes_ago=0, identity_key_ids=None):
    from core.models import Challenge, ChallengeMethod, ChallengeStatus

    return Challenge.objects.create(
        application=application, client_id=client_id, method=ChallengeMethod.OTP,
        status=ChallengeStatus.PASSED, expires_at=timezone.now() + timedelta(minutes=15),
        resolved_at=timezone.now() - timedelta(minutes=minutes_ago),
        identity_key_ids=identity_key_ids or [],
    )


class TestConsume:
    def consume(self, application, client_id, challenge_id):
        from core.services.challenge_replay import ChallengeReplay
        return ChallengeReplay.consume(application=application, client_id=client_id, challenge_id=challenge_id)

    def test_a_cleared_challenge_is_accepted_and_counted(self, application):
        challenge = passed_challenge(application)

        message = self.consume(application, "actor_1", str(challenge.id))

        assert message.code == "challenge_passed"
        assert message.context["passed_challenge"] is True
        challenge.refresh_from_db()
        assert challenge.replays == 1

    def test_unknown_or_foreign_challenges_are_rejected(self, application, second_application):
        import uuid
        challenge = passed_challenge(second_application)

        assert self.consume(application, "actor_1", str(uuid.uuid4())).context["reason"] == "unknown"
        assert self.consume(application, "actor_1", str(challenge.id)).context["reason"] == "unknown"

    def test_a_pending_challenge_is_not_a_pass(self, application):
        from core.models import ChallengeStatus

        challenge = passed_challenge(application)
        challenge.status = ChallengeStatus.PENDING
        challenge.save()

        assert self.consume(application, "actor_1", str(challenge.id)).context["reason"] == "not_passed"

    def test_another_accounts_challenge_is_rejected(self, application):
        challenge = passed_challenge(application, client_id="actor_1")
        assert self.consume(application, "actor_2", str(challenge.id)).context["reason"] == "different_account"

    def test_an_old_pass_is_rejected(self, application):
        challenge = passed_challenge(application, minutes_ago=20)
        assert self.consume(application, "actor_1", str(challenge.id)).context["reason"] == "too_old"

    def test_three_replays_and_no_more(self, application):
        challenge = passed_challenge(application)

        for _ in range(3):
            assert self.consume(application, "actor_1", str(challenge.id)).code == "challenge_passed"

        assert self.consume(application, "actor_1", str(challenge.id)).context["reason"] == "exhausted"


class TestTheEngine:
    def test_a_passed_challenge_waives_the_step_up_and_discounts_the_score(self):
        from core.scoring import RiskEngine

        engine = RiskEngine()
        messages = [dict(code="disposable_email_domain", text="", context={})]

        before = engine.calculate_risk(messages)
        assert before.should_challenge is True

        after = engine.calculate_risk(messages + [
            dict(code="challenge_passed", text="", context=dict(score=0.0, passed_challenge=True)),
        ])

        assert after.should_challenge is False
        assert after.total_score == pytest.approx(before.total_score * (1 - RiskEngine.CHALLENGE_PASSED_DISCOUNT))
        assert after.metadata["passed_challenges"] == ["challenge_passed"]

    def test_it_never_touches_a_hard_block(self):
        from core.scoring import RiskEngine

        result = RiskEngine().calculate_risk([
            dict(code="sanctioned_address", text="", context=dict(severity=1.0, hard_block=True)),
            dict(code="challenge_passed", text="", context=dict(score=0.0, passed_challenge=True)),
        ])

        assert result.should_block is True


class TestReplayThroughTheAuditor:
    def test_replaying_with_the_challenge_lowers_the_decision(self, application, no_geoip):
        first = signup(application, client_id="actor_1")
        assert first.should_challenge or first.should_review

        challenge = passed_challenge(application, client_id="actor_1")
        replayed = signup(application, client_id="actor_1", challenge_id=str(challenge.id))

        assert "challenge_passed" in replayed.factors
        assert replayed.should_challenge is False
        assert replayed.risk_score < first.risk_score

    def test_a_bad_challenge_id_changes_nothing_but_is_reported(self, application, no_geoip):
        import uuid

        result = signup(application, client_id="actor_1", challenge_id=str(uuid.uuid4()))

        assert "challenge_replay_rejected" in result.factors
        assert "challenge_passed" not in result.factors


class TestIssuedChallenges:
    def test_the_decision_issues_the_challenge_when_the_policy_says_so(self, application, no_geoip):
        from core.models import Challenge

        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        result = signup(application, client_id="actor_1")

        assert result.should_challenge is True
        assert result.challenge is not None
        assert result.challenge["method"] == "otp"
        assert len(result.challenge["code"]) == 6

        challenge = Challenge.objects.get(id=result.challenge["id"])
        assert challenge.client_id == "actor_1"
        assert str(challenge.audit_log_id) == result.audit_id
        assert challenge.secret_hash == challenge.hash_code(result.challenge["code"])

    def test_without_a_method_nothing_is_issued(self, application, no_geoip):
        result = signup(application, client_id="actor_1")
        assert result.should_challenge is True
        assert result.challenge is None

    def test_shadow_issues_nothing(self, application, no_geoip):
        application.enforcement = "shadow"
        application.save(update_fields=["enforcement"])
        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        result = signup(application, client_id="actor_1")

        assert result.would_challenge is True
        assert result.challenge is None

    def test_the_whole_loop(self, application, no_geoip):
        """Decide, issue, verify, replay: one puzzle, then through."""
        from core.models import Challenge
        from tests.unit.test_challenges import verify

        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        first = signup(application, client_id="actor_1")
        challenge = Challenge.objects.get(id=first.challenge["id"])

        _, passed, _ = verify(challenge, first.challenge["code"])
        assert passed

        replayed = signup(application, client_id="actor_1", challenge_id=first.challenge["id"])
        assert replayed.should_challenge is False
        assert replayed.challenge is None


class TestChallengePassedRule:
    def test_a_recent_pass_on_the_actors_keys_is_read(self, application, no_geoip):
        """
        The pass lands on the identity keys the decision resolved, so the next
        event from the same keys sees it without a challenge id.
        """
        from core.models import Challenge
        from tests.unit.test_challenges import verify

        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        first = signup(application, client_id="actor_1")
        challenge = Challenge.objects.get(id=first.challenge["id"])
        verify(challenge, first.challenge["code"])

        later = signup(application, client_id="actor_1")

        assert "recent_challenge_passed" in later.factors
        assert later.should_challenge is False

    def test_failures_after_the_pass_cancel_it(self, application, no_geoip):
        from core.models import Challenge
        from core.services.network_reputation import NetworkReputation
        from tests.unit.test_challenges import verify

        policy = application.policy
        policy.challenge_method = "otp"
        policy.save(update_fields=["challenge_method"])

        first = signup(application, client_id="actor_1")
        challenge = Challenge.objects.get(id=first.challenge["id"])
        verify(challenge, first.challenge["code"])
        for _ in range(2):
            NetworkReputation.record(
                identity_key_ids=challenge.identity_key_ids, application=application,
                outcome="challenge_failed",
            )

        later = signup(application, client_id="actor_1")

        assert "recent_challenge_passed" not in later.factors
