"""
Tests for the credential surface: the authentication event and the rules
that read a takeover out of the sequence of credential actions.

The centrepiece is a replay of a real attack. On 20 October 2026 a single
actor on a Moldovan VPS took over eighteen live accounts on a card issuer in
under an hour. The method on every account was the same: request a password
reset, then log in six to thirty-one seconds later — through two-factor, and
through Google sign-in — with `python-requests`, `curl` or `okhttp`. It then
sent a one-dollar test payout from the first account to a fresh address. The
reset flow was already rate-limited and attempt-capped; the attacker was not
guessing, so none of that fired. The interval was the only tell, and FLIT had
no event that carried it.

Each behaviour is checked twice: that it fires on the attack, and that the
owner doing the honest version of the same thing does not trip it.
"""

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from django.utils import timezone


# A hosting-provider address the attack actually used. 35.0.0.0/8 is in the
# cloud fallback ranges, so it reads as a datacenter without GeoIP.
ATTACKER_IP = "35.240.149.171"
SCRIPT = "python-requests/2.31.0"

# A customer at home in Lagos on an ordinary browser.
OWNER_IP = "102.91.133.202"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"

# The first eight accounts taken, in order, with the measured interval from
# reset requested to logged in. Names are placeholders; the timings are real.
ATTACK_SEQUENCE = [
    ("victim_01", 31, True),
    ("victim_02", 21, True),
    ("victim_03", 16, True),
    ("victim_04", 17, True),
    ("victim_05", 9, True),
    ("victim_06", 21, False),
    ("victim_07", 16, False),
    ("victim_08", 10, True),
]


def codes(result):
    return {reason.code for reason in result.reasons}


def audit(application, event):
    from core.audit.auditor import Auditor

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=None),
    ):
        return asyncio.run(
            Auditor.audit(event, application.policy, send_alerts=False)
        )


def authenticate(application, *, client_id, action, ip_address, user_agent,
                 second_factor=None, auth_method="password", status=None,
                 event_id=None):
    """One credential action, audited the way a merchant's auth handler would."""
    from core.audit.events import AuthenticationEvent

    return audit(application, AuthenticationEvent(
        id=event_id or f"{client_id}:{action}:{timezone.now().timestamp()}",
        client_id=client_id,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        second_factor=second_factor,
        auth_method=auth_method,
        status=status,
    ))


def backdate(application, *, client_id, action, seconds):
    """Move the most recent recorded `action` for an account into the past."""
    from core.audit.models import AuditLog

    log = (
        AuditLog.objects
        .filter(application_id=application.id, actor_id=client_id, action=action)
        .order_by("-timestamp")
        .first()
    )
    assert log is not None, f"no {action} recorded for {client_id}"
    AuditLog.objects.filter(id=log.id).update(
        timestamp=timezone.now() - timedelta(seconds=seconds),
    )


def reset_then_login(application, *, client_id, seconds, ip_address, user_agent,
                     second_factor=None, auth_method="password"):
    """A reset request, then a login `seconds` later, both from one origin."""
    from core.audit.events import AuthenticationEvent

    authenticate(
        application, client_id=client_id,
        action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
        ip_address=ip_address, user_agent=user_agent,
    )
    backdate(
        application, client_id=client_id,
        action=AuthenticationEvent.PASSWORD_RESET_REQUESTED, seconds=seconds,
    )
    return authenticate(
        application, client_id=client_id,
        action=AuthenticationEvent.LOGIN,
        ip_address=ip_address, user_agent=user_agent,
        second_factor=second_factor, auth_method=auth_method,
    )


def withdraw(application, *, client_id, amount, to_address, ip_address, user_agent):
    """A crypto payout, audited the way a merchant's withdrawal handler would."""
    from core.audit.events import TransactionEvent

    return audit(application, TransactionEvent(
        id=f"{client_id}:withdrawal:{to_address}",
        client_id=client_id,
        type="debit",
        amount=amount,
        currency_code="USD",
        chain="polygon",
        asset="usdc",
        counterparty_address=to_address,
        ip_address=ip_address,
        user_agent=user_agent,
        status="success",
    ))


class TestAuthenticationEvent:
    def test_requires_an_account_and_a_known_action(self):
        from core.audit.events import AuthenticationEvent

        errors = AuthenticationEvent(id="e1", client_id="u1", action="teleport").verify()
        assert [error.path for error in errors] == ["action"]

        errors = AuthenticationEvent(id="e1", action="login").verify()
        assert [error.path for error in errors] == ["client_id"]

        assert AuthenticationEvent(id="e1", client_id="u1", action="login").verify() == []

    def test_the_account_is_the_client_not_the_event(self):
        from core.audit.events import AuthenticationEvent

        event = AuthenticationEvent(id="evt_9", client_id="user_1", action="login")
        assert event.account_id == "user_1"

    def test_a_failed_login_is_a_failure_without_being_told(self):
        from core.audit.events import AuthenticationEvent

        assert not AuthenticationEvent(id="e", client_id="u", action="login_failed").succeeded
        assert AuthenticationEvent(id="e", client_id="u", action="login").succeeded
        assert not AuthenticationEvent(
            id="e", client_id="u", action="login", status="failure",
        ).succeeded

    def test_the_api_accepts_it_as_an_audit_mode(self):
        from api.parsers.parse_audit_inputs import modes_dict
        from core.audit.events import AuthenticationEvent

        assert modes_dict["authentication"] is AuthenticationEvent

    def test_it_is_recorded_as_authentication_history(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent
        from core.audit.models import AuditLog, AuditLogCategory

        authenticate(
            application, client_id="user_1",
            action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )

        log = AuditLog.objects.get(actor_id="user_1")
        assert log.category == AuditLogCategory.AUTHENTICATION
        assert log.action == "password_reset_requested"
        assert log.outcome == "success"
        assert log.resource_type == "authentication"
        assert log.context["action"] == "password_reset_requested"


class TestResetToLogin:
    def test_a_login_seconds_after_a_reset_is_caught(self, application, no_geoip):
        result = reset_then_login(
            application, client_id="victim", seconds=16,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )

        reason = next(r for r in result.reasons if r.code == "reset_then_login")
        assert reason.context["severity"] == 1.0
        assert 15 <= reason.context["seconds_since_reset_request"] <= 17
        assert reason.context["same_origin_as_reset"] is True

    def test_severity_falls_as_the_interval_grows(self, application, no_geoip):
        from core.audit.rules import ResetToLoginRule

        assert ResetToLoginRule.grade(10, 90) == 1.0
        assert ResetToLoginRule.grade(45, 90) == 0.8
        assert ResetToLoginRule.grade(80, 90) == 0.6

    def test_an_owner_reading_their_email_is_left_alone(self, application, no_geoip):
        result = reset_then_login(
            application, client_id="owner", seconds=240,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )

        assert "reset_then_login" not in codes(result)
        assert not result.should_challenge
        assert not result.should_block

    def test_a_login_with_no_reset_behind_it_is_left_alone(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent

        result = authenticate(
            application, client_id="owner",
            action=AuthenticationEvent.LOGIN,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )

        assert "reset_then_login" not in codes(result)

    def test_a_stale_reset_request_does_not_count(self, application, no_geoip):
        result = reset_then_login(
            application, client_id="owner", seconds=3600,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )

        assert "reset_then_login" not in codes(result)

    def test_another_accounts_reset_does_not_count(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent

        authenticate(
            application, client_id="someone_else",
            action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )
        result = authenticate(
            application, client_id="owner",
            action=AuthenticationEvent.LOGIN,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )

        assert "reset_then_login" not in codes(result)


class TestAutomatedCredentialAction:
    def test_a_script_on_a_hosting_provider_is_the_strongest_finding(
        self, application, no_geoip,
    ):
        from core.audit.events import AuthenticationEvent

        result = authenticate(
            application, client_id="victim",
            action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
            ip_address=ATTACKER_IP, user_agent=SCRIPT,
        )

        reason = next(r for r in result.reasons if r.code == "automated_credential_action")
        assert reason.context["severity"] == 1.0
        assert reason.context["datacenter"] is True
        assert reason.context["bot_type"] == "http_client"

    def test_a_script_through_two_factor_had_the_secret(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent

        result = authenticate(
            application, client_id="victim",
            action=AuthenticationEvent.LOGIN,
            ip_address=OWNER_IP, user_agent="okhttp/4.9.2",
            second_factor=True,
        )

        reason = next(r for r in result.reasons if r.code == "automated_credential_action")
        assert reason.context["severity"] == 0.9

    def test_a_person_on_a_vpn_is_not_a_script(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent

        result = authenticate(
            application, client_id="traveller",
            action=AuthenticationEvent.LOGIN,
            ip_address=ATTACKER_IP, user_agent=BROWSER,
        )

        assert "automated_credential_action" not in codes(result)

    def test_a_script_doing_something_harmless_is_not_this_rule(
        self, application, no_geoip,
    ):
        from core.audit.events import AuthenticationEvent

        result = authenticate(
            application, client_id="victim",
            action=AuthenticationEvent.TWO_FACTOR_ENABLED,
            ip_address=ATTACKER_IP, user_agent=SCRIPT,
        )

        # Bot detection still sees it; this rule is about credential actions.
        assert "automated_credential_action" not in codes(result)
        assert "bot_detected:http_client" in codes(result)


class TestCredentialResetStorm:
    def test_three_accounts_reset_from_one_ip_is_a_storm(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent

        results = [
            authenticate(
                application, client_id=f"victim_{index}",
                action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
                ip_address=OWNER_IP, user_agent=BROWSER,
            )
            for index in range(3)
        ]

        assert "credential_reset_storm" not in codes(results[0])
        assert "credential_reset_storm" not in codes(results[1])

        reason = next(r for r in results[2].reasons if r.code == "credential_reset_storm")
        assert reason.context["accounts"] == 3
        assert reason.context["accounts_with_reset"] == 3
        assert reason.context["severity"] == 0.8

    def test_one_owner_resetting_twice_is_not_a_storm(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent

        for _ in range(3):
            result = authenticate(
                application, client_id="forgetful_owner",
                action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
                ip_address=OWNER_IP, user_agent=BROWSER,
            )

        assert "credential_reset_storm" not in codes(result)

    def test_a_household_logging_in_is_not_a_storm(self, application, no_geoip):
        from core.audit.events import AuthenticationEvent

        for client_id in ("parent", "partner"):
            result = authenticate(
                application, client_id=client_id,
                action=AuthenticationEvent.LOGIN,
                ip_address=OWNER_IP, user_agent=BROWSER,
            )

        assert "credential_reset_storm" not in codes(result)

    def test_the_storm_is_counted_per_merchant(
        self, application, second_application, no_geoip,
    ):
        from core.audit.events import AuthenticationEvent

        for index in range(3):
            authenticate(
                application, client_id=f"victim_{index}",
                action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
                ip_address=OWNER_IP, user_agent=BROWSER,
            )

        result = authenticate(
            second_application, client_id="their_customer",
            action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
            ip_address=OWNER_IP, user_agent=BROWSER,
        )

        assert "credential_reset_storm" not in codes(result)


class TestOctober2026Replay:
    """
    The attack that prompted all of this, replayed end to end.

    Ground truth: every one of these accounts was taken, and FLIT as it stood
    had no event the sequence could have been reported through.
    """

    def replay(self, application):
        results = []

        for client_id, seconds, second_factor in ATTACK_SEQUENCE:
            results.append(
                reset_then_login(
                    application, client_id=client_id, seconds=seconds,
                    ip_address=ATTACKER_IP, user_agent=SCRIPT,
                    second_factor=second_factor,
                )
            )

        return results

    def test_the_first_takeover_is_caught_on_its_own(self, application, no_geoip):
        results = self.replay(application)
        first = results[0]

        assert "reset_then_login" in codes(first)
        assert "automated_credential_action" in codes(first)
        assert first.should_block, (first.risk_score, codes(first))

    def test_the_takeover_through_two_factor_is_caught(self, application, no_geoip):
        results = self.replay(application)
        reasons = {r.code: r for r in results[0].reasons}

        assert reasons["reset_then_login"].context["second_factor"] is True
        assert reasons["automated_credential_action"].context["second_factor"] is True

    def test_the_whole_sequence_is_blocked(self, application, no_geoip):
        results = self.replay(application)

        assert all(result.should_block for result in results), [
            (client_id, round(result.risk_score, 3))
            for (client_id, _, _), result in zip(ATTACK_SEQUENCE, results)
        ]

    def test_the_list_being_worked_is_seen_by_the_third_account(
        self, application, no_geoip,
    ):
        results = self.replay(application)

        assert "credential_reset_storm" not in codes(results[0])
        assert "credential_reset_storm" in codes(results[2])
        assert "credential_reset_storm" in codes(results[-1])

    def test_the_test_payout_after_the_takeover_is_stopped(
        self, application, no_geoip,
    ):
        # The victim had paid out to their own wallets before, so a new
        # destination means something here.
        for index, address in enumerate((
            "0x9FAaA604fD66e799b792e56a84181Be493b7D8F3",
            "0x1111111111111111111111111111111111111111",
        )):
            withdraw(
                application, client_id="victim_01", amount=100.0 + index,
                to_address=address, ip_address=OWNER_IP, user_agent=BROWSER,
            )

        self.replay(application)

        result = withdraw(
            application, client_id="victim_01", amount=1.0,
            to_address="0x629a0fa7326f6a61a85db2622504e518afd98c5b",
            ip_address=ATTACKER_IP, user_agent=SCRIPT,
        )

        assert "account_takeover_risk" in codes(result)
        assert "new_withdrawal_address" in codes(result)
        assert result.should_block or result.should_challenge, codes(result)

    def test_a_manipulation_after_the_takeover_is_caught_on_the_spot(
        self, application, no_geoip,
    ):
        from core.audit.events import AuthenticationEvent

        self.replay(application)

        result = authenticate(
            application, client_id="victim_01",
            action=AuthenticationEvent.EMAIL_CHANGE,
            ip_address=ATTACKER_IP, user_agent=SCRIPT,
        )

        assert "account_takeover_risk" in codes(result)
        assert result.should_block

    def test_the_owners_in_the_same_hour_are_untouched(self, application, no_geoip):
        """
        While the attack runs, real customers reset passwords and log in.
        None of them should be stopped.
        """
        from core.audit.events import AuthenticationEvent

        self.replay(application)

        slow_reset = reset_then_login(
            application, client_id="owner_resetting", seconds=200,
            ip_address="197.210.70.11", user_agent=BROWSER,
        )
        plain_login = authenticate(
            application, client_id="owner_logging_in",
            action=AuthenticationEvent.LOGIN,
            ip_address="41.190.3.44", user_agent=BROWSER,
            second_factor=True,
        )
        google_login = authenticate(
            application, client_id="owner_with_google",
            action=AuthenticationEvent.LOGIN,
            ip_address="154.160.51.159",
            user_agent="Mozilla/5.0 (Linux; Android 14) Chrome/120.0 Mobile",
            auth_method="google",
        )

        for result in (slow_reset, plain_login, google_login):
            assert not result.should_block, codes(result)
            assert not result.should_challenge, codes(result)

    def test_the_owner_who_opened_their_app_afterwards_is_not_blamed(
        self, application, no_geoip,
    ):
        """
        One victim opened the real mobile app from home two minutes after the
        hostile login. That is a person reacting to an alert, not the attack.
        """
        from core.audit.events import AuthenticationEvent

        self.replay(application)
        backdate(
            application, client_id="victim_01",
            action=AuthenticationEvent.PASSWORD_RESET_REQUESTED, seconds=133,
        )

        result = authenticate(
            application, client_id="victim_01",
            action=AuthenticationEvent.LOGIN,
            ip_address="45.150.147.101",
            user_agent="Dart/3.4 (dart:io)",
            auth_method="google",
        )

        # The reset is now over a minute old, and the client is the real
        # app. The interval rule stays quiet; nothing here is a script.
        assert "reset_then_login" not in codes(result)
        assert "automated_credential_action" not in codes(result)
