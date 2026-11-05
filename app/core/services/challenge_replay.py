"""
Replaying a decision with the challenge it asked for, now cleared.

The step-up loop is: FLIT says "challenge", the merchant challenges, the user
clears it, the merchant asks again with the challenge id. The replay has to
be bounded — one cleared challenge is not a pass for every request this hour
— and it has to be checked: the right application, the right account,
recently cleared, not yet spent.
"""

import logging
from datetime import timedelta

from django.utils import timezone
from devkit.message import Message

from core.models.challenge import Challenge, ChallengeStatus


logger = logging.getLogger(__name__)


class ChallengeReplay:
    # A cleared challenge may be presented this many times.
    MAX_REPLAYS = 3
    # And for this long after it was cleared.
    WINDOW_MINUTES = 15

    @classmethod
    def consume(cls, *, application, client_id, challenge_id):
        """
        Spend one replay of a cleared challenge. Returns a Message for the
        decision: `challenge_passed` with `passed_challenge=True` when the
        challenge is good, otherwise `challenge_replay_rejected` with why.
        """
        rejected = lambda reason: Message(
            code="challenge_replay_rejected",
            path="challenge_id",
            text=f"The challenge presented with this event was not accepted ({reason})",
            context=dict(score=0.0, reason=reason, challenge_id=str(challenge_id)),
        )

        challenge = (
            Challenge.objects
            .select_for_update(of=("self",))
            .filter(id=challenge_id, application=application)
            .first()
        ) if Challenge.objects.filter(id=challenge_id, application=application).exists() else None

        if challenge is None:
            return rejected("unknown")
        if challenge.status != ChallengeStatus.PASSED or challenge.resolved_at is None:
            return rejected("not_passed")
        if client_id and challenge.client_id and str(challenge.client_id) != str(client_id):
            return rejected("different_account")
        if timezone.now() - challenge.resolved_at > timedelta(minutes=cls.WINDOW_MINUTES):
            return rejected("too_old")
        if challenge.replays >= cls.MAX_REPLAYS:
            return rejected("exhausted")

        challenge.replays += 1
        challenge.save(update_fields=["replays"])

        return Message(
            code="challenge_passed",
            path="challenge_id",
            text="The actor cleared the step-up this decision asked for",
            context=dict(
                score=0.0,
                challenge_id=str(challenge.id),
                method=challenge.method,
                replay=challenge.replays,
                passed_challenge=True,
            ),
        )
