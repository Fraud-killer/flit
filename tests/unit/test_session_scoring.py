"""
Tests for session scoring: reading an origin's hour as one thing.

The centrepiece is an evasive replay. Take the October 2026 takeover and
give the attacker what it would learn from being caught by the event rules:
slow the reset-to-login to 150 seconds, past `ResetToLoginRule`'s window,
and change the client string on every account. Each event now passes the
per-event rules. The session does not — it is still one address working six
accounts it did not create, with the same reset, login, payout motif, at a
cadence no person keeps.

Each behaviour is checked twice: that it fires on the attack, and that the
shared-address cases an honest merchant sees every hour — an office, a
household, a carrier-NAT city — do not trip it.
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from tests.unit.test_credential_takeover import (
    BROWSER, OWNER_IP, audit, authenticate, codes,
)


ATTACKER_IP = "217.156.62.23"
FRESH_ADDRESS = "0x629a0fa7326f6a61a85db2622504e518afd98c5b"

# One client per account: what a loop does once a user-agent list caught it.
ROTATING_CLIENTS = [
    "curl/8.5.0",
    "python-requests/2.31.0",
    "okhttp/4.9.2",
    "Go-http-client/1.1",
    "node-fetch/2.6.7",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
]

# Past the 90-second window the per-event rule reads.
SLOWED_RESET_TO_LOGIN = 150


def backdate_event(application, event_id, seconds_ago):
    from core.audit.models import AuditLog

    updated = AuditLog.objects.filter(
        application_id=application.id, resource_id=event_id,
    ).update(timestamp=timezone.now() - timedelta(seconds=seconds_ago))
    assert updated == 1, f"event {event_id} was not recorded"


def login(application, *, client_id, ip_address, user_agent, seconds_ago, **kwargs):
    from core.audit.events import AuthenticationEvent

    event_id = f"{client_id}:login:{seconds_ago}"
    result = authenticate(
        application, client_id=client_id, action=AuthenticationEvent.LOGIN,
        ip_address=ip_address, user_agent=user_agent, event_id=event_id, **kwargs,
    )
    backdate_event(application, event_id, seconds_ago)
    return result


def reset_request(application, *, client_id, ip_address, user_agent, seconds_ago):
    from core.audit.events import AuthenticationEvent

    event_id = f"{client_id}:reset:{seconds_ago}"
    result = authenticate(
        application, client_id=client_id,
        action=AuthenticationEvent.PASSWORD_RESET_REQUESTED,
        ip_address=ip_address, user_agent=user_agent, event_id=event_id,
    )
    backdate_event(application, event_id, seconds_ago)
    return result


def payout(application, *, client_id, ip_address, user_agent, seconds_ago, amount=1.0):
    from core.audit.events import TransactionEvent

    event_id = f"{client_id}:payout:{seconds_ago}"
    result = audit(application, TransactionEvent(
        id=event_id, client_id=client_id, type="debit", amount=amount,
        currency_code="USD", chain="polygon", asset="usdc",
        counterparty_address=FRESH_ADDRESS,
        ip_address=ip_address, user_agent=user_agent, status="success",
    ))
    backdate_event(application, event_id, seconds_ago)
    return result


def seed_session(application, *, ip_address, hours_ago, accounts, user_agent=BROWSER,
                 gap_seconds=300):
    """
    Write one past session straight into history, for a baseline.

    Goes through the audit logger rather than the auditor: these are the
    merchant's ordinary hours, and running the rules over them would be slow
    and beside the point.
    """
    from core.audit.logger import AuditLogger
    from core.audit.models import AuditLog, AuditLogCategory, AuditLogLevel

    # Aligned to the hour so the whole session lands in one baseline bucket
    # regardless of what the wall clock says when the test runs.
    start = (timezone.now() - timedelta(hours=hours_ago)).replace(
        minute=0, second=0, microsecond=0,
    )
    for index, client_id in enumerate(accounts):
        log = AuditLogger.log(
            level=AuditLogLevel.INFO,
            category=AuditLogCategory.AUTHENTICATION,
            action="login",
            actor_type="client",
            actor_id=client_id,
            application_id=application.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        AuditLog.objects.filter(id=log.id).update(
            timestamp=start + timedelta(seconds=index * gap_seconds),
        )


class TestClientFamily:
    def test_versions_and_platforms_are_one_client(self):
        from core.services.session_activity import client_family

        assert client_family("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0") == "mozilla"
        assert client_family("Mozilla/5.0 (Linux; Android 14) Chrome/121.0 Mobile") == "mozilla"
        assert client_family("python-requests/2.31.0") == "python-requests"
        assert client_family("python-requests/2.32.1") == "python-requests"

    def test_different_tools_are_different_clients(self):
        from core.services.session_activity import client_family

        families = {client_family(ua) for ua in ROTATING_CLIENTS}
        assert len(families) == len(ROTATING_CLIENTS)

    def test_nothing_is_nothing(self):
        from core.services.session_activity import client_family

        assert client_family(None) is None
        assert client_family("") is None


class TestSessionProfile:
    def test_reads_the_takeover_motif_per_account(self):
        from core.services.session_activity import SessionProfile

        now = timezone.now()

        def at(seconds, action, actor):
            return dict(timestamp=now + timedelta(seconds=seconds), action=action,
                        actor_id=actor, user_agent="curl/8.5.0", category=None, risk_score=None)

        profile = SessionProfile(origin=dict(key="ip", value="x"), events=[
            at(0, "password_reset_requested", "a"),
            at(20, "login", "a"),
            at(40, "transaction_debit", "a"),
            at(60, "password_reset_requested", "b"),
            at(80, "login", "b"),
            # Login before any reset: not the motif.
            at(100, "login", "c"),
            at(120, "email_change", "c"),
        ])

        credential, takeover = profile.motifs()
        assert credential == {"a", "b"}
        assert takeover == {"a"}

        features = profile.features()
        assert features["accounts"] == 3
        assert features["credential_motifs"] == 2
        assert features["takeover_motifs"] == 1
        assert features["median_gap_seconds"] == 20.0
        assert features["gap_regularity"] == 1.0

    def test_credentials_on_accounts_the_origin_did_not_create(self):
        from core.services.session_activity import SessionProfile

        now = timezone.now()

        def at(seconds, action, actor):
            return dict(timestamp=now + timedelta(seconds=seconds), action=action,
                        actor_id=actor, user_agent="curl", category=None, risk_score=None)

        profile = SessionProfile(origin=None, events=[
            at(0, "registration", "fake_1"),
            at(1, "registration", "fake_2"),
            at(2, "registration", "fake_3"),
            at(3, "login", "fake_1"),
            at(4, "password_reset_requested", "victim"),
        ])

        features = profile.features()
        assert features["registrations"] == 3
        assert features["credential_accounts_not_registered"] == 1


class TestSessionBaseline:
    def test_percentiles_come_from_the_merchants_own_hours(self, application):
        from core.services.session_activity import SessionBaseline

        # Forty quiet hours: one person, one browser, each from their own address.
        for index in range(40):
            seed_session(
                application, ip_address=f"102.91.{index}.{index + 1}",
                hours_ago=2 + index, accounts=[f"user_{index}"],
            )

        baseline = SessionBaseline.compute(application=application)

        assert baseline["sessions"] == 40
        assert baseline["accounts_p95"] == 1
        assert baseline["client_families_p95"] == 1

    def test_too_little_history_means_no_baseline(self, application):
        from core.services.session_activity import SessionBaseline

        for index in range(5):
            seed_session(application, ip_address=f"102.91.0.{index + 1}",
                         hours_ago=2 + index, accounts=[f"user_{index}"])

        assert SessionBaseline.compute(application=application) is None
        assert SessionBaseline.load(application=application) == SessionBaseline.DEFAULTS

    def test_a_carrier_nat_merchant_has_a_wider_normal(self, application):
        from core.services.session_activity import SessionBaseline

        # Forty hours where thirty people share each address.
        for index in range(40):
            seed_session(
                application, ip_address=f"197.210.{index}.1", hours_ago=2 + index,
                accounts=[f"user_{index}_{n}" for n in range(30)], gap_seconds=100,
            )

        baseline = SessionBaseline.compute(application=application)
        assert baseline["accounts_p95"] == 30


class TestEvasiveReplay:
    """
    October 2026, replayed by an attacker who has read the event rules.

    Six accounts from one address over fifty minutes. Reset, then login 150
    seconds later, then a one-dollar payout to a fresh address — and a
    different client on every account.
    """

    def replay(self, application, accounts=6):
        results = []

        for index in range(accounts):
            client_id = f"victim_{index:02d}"
            user_agent = ROTATING_CLIENTS[index % len(ROTATING_CLIENTS)]
            start = 3100 - index * 480

            reset = reset_request(
                application, client_id=client_id, ip_address=ATTACKER_IP,
                user_agent=user_agent, seconds_ago=start,
            )
            entered = login(
                application, client_id=client_id, ip_address=ATTACKER_IP,
                user_agent=user_agent, seconds_ago=start - SLOWED_RESET_TO_LOGIN,
            )
            paid = payout(
                application, client_id=client_id, ip_address=ATTACKER_IP,
                user_agent=user_agent, seconds_ago=start - SLOWED_RESET_TO_LOGIN - 120,
            )
            results.append(dict(reset=reset, login=entered, payout=paid))

        return results

    def test_the_slowed_reset_steps_over_the_event_rule(self, application, no_geoip):
        results = self.replay(application)

        # The evasion works against the per-event rule. That is the point.
        assert all("reset_then_login" not in codes(step["login"]) for step in results)

    def test_the_session_is_read_as_a_machine_by_the_third_account(
        self, application, no_geoip,
    ):
        results = self.replay(application)

        assert "machine_session" not in codes(results[0]["reset"])
        assert "machine_session" in codes(results[2]["login"]), codes(results[2]["login"])

        reason = next(r for r in results[-1]["login"].reasons if r.code == "machine_session")
        assert "rotating_clients" in reason.context["signals"]
        assert "many_accounts" in reason.context["signals"]
        assert reason.context["origin"] == dict(key="ip", value=ATTACKER_IP)

    def test_the_motif_repeating_is_the_takeover(self, application, no_geoip):
        results = self.replay(application)

        # Two accounts have been reset, entered and drained by the time the
        # third is touched.
        assert "campaign_motif" in codes(results[2]["reset"])
        reason = next(r for r in results[-1]["payout"].reasons if r.code == "campaign_motif")
        assert reason.context["accounts_taken"] >= 5

    def test_the_later_accounts_are_blocked(self, application, no_geoip):
        results = self.replay(application)

        later = [step["login"] for step in results[2:]]
        assert all(step.should_block for step in later), [
            (round(step.risk_score, 3), sorted(codes(step))) for step in later
        ]

    def test_the_merchants_normal_hour_is_untouched(self, application, no_geoip):
        """
        In the same hour: a household, an office, and a city behind one
        carrier address. None of them look like a machine.
        """
        self.replay(application)

        household = [
            login(application, client_id=who, ip_address=OWNER_IP,
                  user_agent=BROWSER, seconds_ago=1800 - index * 600)
            for index, who in enumerate(("parent", "partner", "teenager"))
        ]

        office = [
            login(application, client_id=f"staff_{index}", ip_address="196.216.2.10",
                  user_agent=BROWSER, seconds_ago=3300 - index * 420)
            for index in range(8)
        ]

        city = [
            login(
                application, client_id=f"subscriber_{index}", ip_address="197.210.70.11",
                user_agent=BROWSER if index % 2 else "Dart/3.4 (dart:io)",
                seconds_ago=3500 - index * 85,
            )
            for index in range(40)
        ]

        for result in household + office + city:
            assert "machine_session" not in codes(result), sorted(codes(result))
            assert not result.should_block
            assert not result.should_challenge


class TestSessionShapeRule:
    def test_too_few_events_say_nothing(self, application, no_geoip):
        results = [
            login(application, client_id=f"u{index}", ip_address=ATTACKER_IP,
                  user_agent=ROTATING_CLIENTS[index], seconds_ago=600 - index * 100)
            for index in range(3)
        ]

        assert all("machine_session" not in codes(result) for result in results)

    def test_a_merchant_baseline_tightens_the_judgement(self, application, no_geoip):
        """
        With a baseline of one account per address, three accounts and three
        clients from one address in an hour is already a machine. Without
        one, the account count alone is not.
        """
        for index in range(40):
            seed_session(application, ip_address=f"102.91.{index}.{index + 1}",
                         hours_ago=2 + index, accounts=[f"user_{index}"])

        results = [
            login(application, client_id=f"acct_{index}", ip_address=ATTACKER_IP,
                  user_agent=ROTATING_CLIENTS[index], seconds_ago=900 - index * 200)
            for index in range(4)
        ]

        reason = next(r for r in results[-1].reasons if r.code == "machine_session")
        assert reason.context["baseline"]["accounts_p95"] == 1
        # The forty seeded hours, plus this session's own earlier events.
        assert reason.context["baseline"]["sessions"] >= 40
        assert "many_accounts" in reason.context["signals"]
        assert "rotating_clients" in reason.context["signals"]

    def test_a_carrier_nat_baseline_loosens_it(self, application, no_geoip):
        for index in range(40):
            seed_session(
                application, ip_address=f"197.210.{index}.1", hours_ago=2 + index,
                accounts=[f"user_{index}_{n}" for n in range(30)], gap_seconds=100,
            )

        results = [
            login(application, client_id=f"subscriber_{index}", ip_address="197.210.70.11",
                  user_agent=BROWSER, seconds_ago=3500 - index * 120)
            for index in range(25)
        ]

        assert all("machine_session" not in codes(result) for result in results)

    def test_registrations_then_other_peoples_credentials(self, application, no_geoip):
        """
        The October actor made two hundred accounts, then went after
        accounts it had not made. The session shows both halves.
        """
        from core.audit.events import RegistrationEvent

        for index in range(4):
            event_id = f"fake_{index}"
            audit(application, RegistrationEvent(
                id=event_id, client_id=event_id, email=f"fake{index}@maxxspace.com",
                country="US", ip_address=ATTACKER_IP, user_agent="curl/8.5.0",
                action="registration",
            ))
            backdate_event(application, event_id, 1200 - index * 60)

        result = reset_request(
            application, client_id="somebody_else", ip_address=ATTACKER_IP,
            user_agent="curl/8.5.0", seconds_ago=0,
        )

        reason = next(r for r in result.reasons if r.code == "machine_session")
        assert "others_credentials" in reason.context["signals"]
        assert reason.context["features"]["registrations"] == 4
