from datetime import timedelta
from django.utils import timezone
from devkit.message import Message

from core.audit.events import AuthenticationEvent
from core.audit.lock_cache import lockcache, LockCache

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class ResetToLoginRule(BaseRule, LockCache):
    """
    A password reset that becomes a login faster than a person can read
    their email.

    A genuine reset has a human in the loop: the code lands in an inbox, the
    owner opens it, types it, chooses a new password, signs in. That takes
    minutes. In the October 2026 takeover every victim went from reset
    requested to logged in within six to thirty-one seconds, on accounts with
    a second factor and on accounts that signed in with Google. No rate limit
    or attempt cap sees that, because the attacker was not guessing — the
    interval is the only place the attack shows.

    Measured from the most recent `password_reset_requested` for the same
    account to this `login` or `password_reset_completed`. Nothing fires above
    the fast window: a slow reset is an ordinary reset.
    """

    techniques = ("F1006.003", "F1006")
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_credential_takeover.py::TestOctober2026Replay"

    # Beyond this a human could plausibly have done it. Below it, graded.
    FAST_SECONDS = 90
    # How far back a reset request still counts. Reset codes expire in
    # minutes, so a request older than this cannot be the one that was used.
    LOOKBACK_SECONDS = 900

    @property
    def applies(self):
        return (
            isinstance(self.event, AuthenticationEvent)
            and self.event.action in (
                AuthenticationEvent.LOGIN,
                AuthenticationEvent.PASSWORD_RESET_COMPLETED,
            )
            and self.event.succeeded
        )

    @lockcache(key="latest_reset_request")
    async def latest_reset_request(self):
        from asgiref.sync import sync_to_async
        from core.audit.models import AuditLog, AuditLogCategory

        client_id = self.event.account_id
        if not client_id:
            return None

        lookback = getattr(self.policy, "reset_lookback_seconds", self.LOOKBACK_SECONDS)
        since = timezone.now() - timedelta(seconds=lookback)

        @sync_to_async
        def fetch():
            return (
                AuditLog.objects
                .filter(
                    application_id=self.application.id,
                    actor_id=client_id,
                    category=AuditLogCategory.AUTHENTICATION,
                    action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
                    timestamp__gte=since,
                )
                .order_by("-timestamp")
                .values("timestamp", "ip_address", "user_agent")
                .first()
            )

        return await fetch()

    @classmethod
    def grade(cls, seconds, fast_seconds):
        """How implausible the interval is for a person, 0 to 1."""
        if seconds <= fast_seconds / 3:
            return 1.0
        if seconds <= fast_seconds * 2 / 3:
            return 0.8
        return 0.6

    async def perform(self):
        request = await self.latest_reset_request()
        if request is None:
            return None

        seconds = (timezone.now() - request["timestamp"]).total_seconds()
        fast_seconds = getattr(self.policy, "reset_to_login_fast_seconds", self.FAST_SECONDS)

        if seconds < 0 or seconds > fast_seconds:
            return None

        same_origin = (
            request["ip_address"] is not None
            and request["ip_address"] == getattr(self.event, "ip_address", None)
        )

        return Message(
            code="reset_then_login",
            path="action",
            text=(
                f"Password reset requested {int(seconds)}s before this "
                f"{self.event.action} — faster than a person reads an email"
            ),
            context=dict(
                severity=self.grade(seconds, fast_seconds),
                seconds_since_reset_request=round(seconds, 1),
                fast_seconds=fast_seconds,
                reset_requested_from=request["ip_address"],
                same_origin_as_reset=same_origin,
                second_factor=event_value(self.event, "second_factor"),
                auth_method=event_value(self.event, "auth_method"),
            ),
        )
