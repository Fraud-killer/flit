from datetime import timedelta
from django.utils import timezone
from devkit.message import Message

from core.audit.events import AuthenticationEvent
from core.audit.lock_cache import lockcache, LockCache

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


class CredentialResetStormRule(BaseRule, LockCache):
    """
    One origin working through many accounts' credentials.

    An account owner resets one password: their own. An IP that requests
    resets for three accounts in an hour, or logs into three, is not an
    owner — it is a list being worked. In October 2026 a single address
    requested resets for twenty-five accounts and logged into eighteen in
    under an hour, and per-account rate limits never noticed, because per
    account it was one request.

    Counted on the IP alone, by design. The identity ladder deliberately
    refuses to count accounts on an ASN, since carrier-grade NAT puts a city
    behind one, and the same caution applies here: a shared office IP can
    hold a handful of real resets, so the threshold is distinct accounts, not
    requests, and it starts above what an office produces in an hour.
    """

    techniques = ("T1110.004", "F1006.003")
    kind = RuleKind.DETECTION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_credential_takeover.py::TestOctober2026Replay"

    WINDOW_MINUTES = 60
    # Distinct accounts, counting this one. Two is a couple sharing a laptop.
    MIN_ACCOUNTS = 3

    @property
    def applies(self):
        return (
            isinstance(self.event, AuthenticationEvent)
            and event_value(self.event, "ip_address") is not None
            and self.event.action in (
                AuthenticationEvent.PASSWORD_RESET_REQUESTED,
                AuthenticationEvent.PASSWORD_RESET_COMPLETED,
                AuthenticationEvent.LOGIN,
                AuthenticationEvent.LOGIN_FAILED,
            )
        )

    @lockcache(key="accounts_touched_from_ip")
    async def accounts_touched_from_ip(self):
        from asgiref.sync import sync_to_async
        from core.audit.models import AuditLog, AuditLogCategory

        window = getattr(self.policy, "reset_storm_window_minutes", self.WINDOW_MINUTES)
        since = timezone.now() - timedelta(minutes=window)
        ip_address = event_value(self.event, "ip_address")

        @sync_to_async
        def fetch():
            rows = (
                AuditLog.objects
                .filter(
                    application_id=self.application.id,
                    category=AuditLogCategory.AUTHENTICATION,
                    ip_address=ip_address,
                    timestamp__gte=since,
                    action__in=[
                        AuthenticationEvent.PASSWORD_RESET_REQUESTED,
                        AuthenticationEvent.PASSWORD_RESET_COMPLETED,
                        AuthenticationEvent.LOGIN,
                        AuthenticationEvent.LOGIN_FAILED,
                    ],
                )
                .values_list("actor_id", "action")
            )

            accounts = set()
            resets = set()
            for actor_id, action in rows:
                if not actor_id:
                    continue
                accounts.add(actor_id)
                if action in AuthenticationEvent.RESET_ACTIONS:
                    resets.add(actor_id)

            return accounts, resets

        return await fetch()

    async def perform(self):
        accounts, resets = await self.accounts_touched_from_ip()

        # This event is not recorded yet, so count it in.
        client_id = self.event.account_id
        if client_id:
            accounts = accounts | {client_id}
            if self.event.is_reset:
                resets = resets | {client_id}

        minimum = getattr(self.policy, "reset_storm_min_accounts", self.MIN_ACCOUNTS)

        # Counted on resets, not logins. Forty people logging in behind one
        # carrier address is an ordinary hour; forty people all forgetting
        # their password behind it is not. The logins touched are reported
        # for the reviewer, and do not decide.
        if len(resets) < minimum:
            return None

        severity = min(1.0, 0.8 + 0.1 * (len(resets) - minimum))

        return Message(
            code="credential_reset_storm",
            path="ip_address",
            text=(
                f"{len(accounts)} accounts' credentials touched from "
                f"{event_value(self.event, 'ip_address')} in the last "
                f"{getattr(self.policy, 'reset_storm_window_minutes', self.WINDOW_MINUTES)} minutes"
            ),
            context=dict(
                severity=severity,
                accounts=len(accounts),
                accounts_with_reset=len(resets),
                minimum=minimum,
                ip_address=event_value(self.event, "ip_address"),
                key="ip",
            ),
        )
