"""
One credential must not be able to drain accounts.

A per-account score cannot see this attack. Each transfer is an ordinary amount
from an ordinary account with a clean history. What gives it away is the view
across accounts: one credential paying people it has never paid, and more money
leaving through it than ever does. These tests hold FLIT to that view, and to
the things that make it safe to run: shadow stops nothing, a stopped credential
stays stopped until a person says otherwise, and a leaked application key can
neither raise a limit nor add trust.

Every identifier here is synthetic.
"""

import threading
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import patch

import pytest
from asgiref.sync import async_to_sync
from django.core.cache import cache
from django.utils import timezone


SATURDAY_EVENING_UTC = datetime(2026, 7, 4, 16, 0, tzinfo=dt_timezone.utc)
FRIDAY_NIGHT_UTC = datetime(2026, 7, 3, 22, 0, tzinfo=dt_timezone.utc)
PARTNER = "partner_key_1"

LIMITS = dict(
    currency="NGN",
    per_initiator={"15m": 6_000_000, "1h": 10_000_000, "24h": 40_000_000},
    per_application={"24h": 500_000_000},
    off_hours=dict(start="20:00", end="07:00", timezone="Africa/Lagos", factor=0.5),
)


@pytest.fixture(autouse=True)
def office_hours():
    """
    Off-hours limits are tighter, so a test that does not set a time would
    pass or fail by the hour the suite runs. Pin it to midday in Lagos today.
    """
    midday = timezone.now().replace(hour=11, minute=0, second=0, microsecond=0)
    with patch("django.utils.timezone.now", return_value=midday):
        yield midday


@pytest.fixture(autouse=True)
def clean_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def bank(application, no_geoip):
    policy = application.policy
    policy.aml_cft_limit = "NGN 5,000,000.00"
    policy.outflow_limits = LIMITS
    policy.beneficiary_control = dict(enabled=True, cooling_hours=72)
    policy.save()
    return application


UNTRUSTED = {"1h": 3_000_000, "24h": 6_000_000}


@pytest.fixture
def open_payer(application, no_geoip):
    """A business that pays new people: the beneficiary rule only reports."""
    policy = application.policy
    policy.aml_cft_limit = "NGN 5,000,000.00"
    policy.outflow_limits = dict(LIMITS, per_initiator_untrusted=UNTRUSTED)
    policy.beneficiary_control = dict(enabled=True, cooling_hours=72)
    policy.shadow_rules = ["UnknownBeneficiaryRule"]
    policy.save()
    return application


@pytest.fixture
def limits_only(application, no_geoip):
    policy = application.policy
    policy.aml_cft_limit = "NGN 5,000,000.00"
    policy.outflow_limits = LIMITS
    policy.save()
    return application


counter = iter(range(10_000_000))


def transfer(app, *, client="merchant_a", beneficiary="0000000001", bank_code="058", amount=1_000_000,
             initiator=PARTNER, at=None, currency="NGN", send_alerts=True, **extra):
    from core.audit.auditor import Auditor
    from core.audit.events import TransactionEvent

    event = TransactionEvent(
        id=f"tx_{next(counter)}", type="debit", amount=amount, currency_code=currency,
        client_id=client, counterparty_id=beneficiary, counterparty_bank=bank_code,
        initiator_id=initiator, channel="nip", **extra,
    )

    app = type(app).objects.get(id=app.id)
    with patch("django.utils.timezone.now", return_value=at or timezone.now()):
        return async_to_sync(Auditor.audit)(event, app.policy, send_alerts=send_alerts)


def trust(app, *, client="merchant_a", beneficiary="0000000001", bank_code="058", initiator=PARTNER):
    from core.services.money_out import MoneyOut

    MoneyOut.approve(app, [dict(
        initiator_id=initiator, client_id=client, counterparty_id=beneficiary, counterparty_bank=bank_code,
    )], user=app.organization.owner)


def set_enforcement(app, value):
    app.enforcement = value
    app.save(update_fields=["enforcement"])


def client_as(entity):
    from rest_framework.test import APIClient
    from core.auth.actor import Actor

    client = APIClient()
    client.force_authenticate(user=None, token=Actor(entity))
    return client


class TestUnknownBeneficiary:
    def test_a_credential_paying_someone_new_is_refused_on_the_first_transfer(self, bank):
        result = transfer(bank)

        assert result.should_block is True
        assert "unknown_beneficiary" in result.factors

    def test_a_clean_account_history_does_not_soften_it(self, bank):
        trust(bank)
        for _ in range(5):
            assert transfer(bank).should_block is False

        assert transfer(bank, beneficiary="0000000099").should_block is True

    def test_a_trusted_beneficiary_passes(self, bank):
        trust(bank)

        assert transfer(bank).should_block is False

    def test_the_same_account_number_at_another_bank_is_someone_else(self, bank):
        trust(bank, bank_code="058")

        assert transfer(bank, bank_code="011").should_block is True

    def test_trust_does_not_carry_to_another_credential_or_account(self, bank):
        trust(bank)

        assert transfer(bank, initiator="partner_key_2").should_block is True
        assert transfer(bank, client="merchant_b").should_block is True

    def test_a_refused_transfer_teaches_nothing(self, bank):
        from core.models import InitiatorBeneficiary

        transfer(bank)

        assert not InitiatorBeneficiary.objects.exists()

    def test_a_link_is_trusted_only_after_the_cooling_period(self, bank):
        set_enforcement(bank, "shadow")
        now = timezone.now()
        assert transfer(bank, at=now).would_block is True

        assert transfer(bank, at=now + timedelta(hours=71)).would_block is True
        assert "unknown_beneficiary" not in transfer(bank, at=now + timedelta(hours=73)).factors

    def test_fraud_ends_trust_however_it_was_earned(self, bank):
        from core.models import AuditLog
        from core.services.money_out import MoneyOut

        trust(bank)
        decision = AuditLog.objects.get(id=transfer(bank).audit_id)
        decision.label = "fraud"
        decision.save(update_fields=["label"])
        MoneyOut.on_label(decision)

        result = transfer(bank)
        assert result.should_block is True
        assert "unknown_beneficiary" in result.factors

    def test_a_debit_that_does_not_say_who_is_reviewed(self, bank):
        result = transfer(bank, initiator=None)

        assert "beneficiary_unverified" in result.factors
        assert result.should_review is True

    def test_a_policy_block_can_name_the_credential(self, bank):
        trust(bank)
        policy = bank.policy
        policy.rules = dict(block=[dict(subject="initiator", pattern=PARTNER, reason="revoked")])
        policy.save()

        assert transfer(bank).should_block is True


class TestOutflowBreaker:
    def test_transfers_under_the_limit_pass(self, limits_only):
        at = SATURDAY_EVENING_UTC
        assert transfer(limits_only, amount=3_000_000, at=at).should_block is False
        assert transfer(limits_only, amount=3_000_000, at=at).should_block is False

    def test_the_transfer_that_crosses_the_limit_is_refused_and_trips_the_credential(self, limits_only):
        from core.models import OutflowTrip

        at = SATURDAY_EVENING_UTC
        transfer(limits_only, amount=4_000_000, at=at)
        result = transfer(limits_only, client="merchant_b", amount=4_000_000, at=at)

        assert result.should_block is True
        assert "outflow_limit_exceeded" in result.factors
        trip = OutflowTrip.objects.get(scope_kind="initiator")
        assert trip.scope_value == PARTNER
        assert trip.window == "15m"

    def test_a_trip_opens_a_case_for_a_person(self, limits_only):
        from core.models import Case

        at = SATURDAY_EVENING_UTC
        transfer(limits_only, amount=7_000_000, at=at)

        assert Case.objects.filter(application=limits_only, priority="high").exists()

    def test_a_tripped_credential_stays_stopped_after_the_window_slides(self, limits_only):
        at = SATURDAY_EVENING_UTC
        transfer(limits_only, amount=7_000_000, at=at)

        later = transfer(limits_only, amount=1_000, at=at + timedelta(days=3))

        assert later.should_block is True
        assert "outflow_trip_active" in later.factors

    def test_another_credential_keeps_working(self, limits_only):
        at = SATURDAY_EVENING_UTC
        transfer(limits_only, amount=7_000_000, at=at)

        assert transfer(limits_only, initiator="partner_key_2", amount=1_000_000, at=at).should_block is False

    def test_a_refused_amount_does_not_count_as_having_left(self, limits_only):
        from core.services.outflow_window import OutflowWindow

        at = SATURDAY_EVENING_UTC
        transfer(limits_only, amount=7_000_000, at=at)

        _, breaches = OutflowWindow.reserve(
            limits_only.id, [("initiator", PARTNER)], 100,
            {"initiator": {"15m": 6_999_999_99}}, at,
        )
        assert breaches == []

    def test_a_tighter_limit_applies_off_hours(self, limits_only):
        amount = 3_500_000

        assert transfer(limits_only, amount=amount, at=SATURDAY_EVENING_UTC).should_block is False
        assert transfer(limits_only, initiator="night", amount=amount, at=FRIDAY_NIGHT_UTC).should_block is True

    def test_an_amount_in_another_currency_is_not_waved_through(self, limits_only):
        result = transfer(limits_only, currency="USD", amount=100)

        assert result.should_block is True
        assert "outflow_unmeasured" in result.factors

    def test_it_can_be_set_to_review_a_debit_it_cannot_measure(self, limits_only):
        policy = limits_only.policy
        policy.outflow_limits = dict(LIMITS, fail="review")
        policy.save()

        result = transfer(limits_only, currency="USD", amount=100)

        assert "outflow_unmeasured" in result.factors
        assert result.should_review is True
        assert not any(r.context.get("hard_block") for r in result.reasons)

    def test_a_cache_that_cannot_be_reached_refuses_the_transfer(self, limits_only):
        with patch("core.services.outflow_window.cache.incr", side_effect=ConnectionError("down")):
            result = transfer(limits_only)

        assert result.should_block is True
        assert result.degraded[0]["rule"] == "OutflowBreakerRule"

    def test_a_replay_of_history_spends_nothing(self, limits_only):
        at = SATURDAY_EVENING_UTC
        for _ in range(4):
            result = transfer(limits_only, amount=4_000_000, at=at, send_alerts=False)
            assert "outflow_limit_exceeded" not in result.factors


class TestConcurrency:
    def test_a_burst_cannot_pass_together(self, db):
        from core.services.outflow_window import OutflowWindow

        at = SATURDAY_EVENING_UTC
        limit, amount = 10_000_000, 1_000_000
        accepted, lock = [], threading.Lock()

        def send():
            reservation, breaches = OutflowWindow.reserve(
                "app", [("initiator", PARTNER)], amount, {"initiator": {"1h": limit}}, at,
            )
            if breaches:
                OutflowWindow.release(reservation)
                return
            with lock:
                accepted.append(amount)

        threads = [threading.Thread(target=send) for _ in range(64)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sum(accepted) <= limit
        assert accepted


class TestShadow:
    def test_shadow_reports_the_stop_and_stops_nothing(self, bank):
        from core.models import OutflowTrip

        set_enforcement(bank, "shadow")
        result = transfer(bank, amount=7_000_000, at=SATURDAY_EVENING_UTC)

        assert result.should_block is False
        assert result.would_block is True
        assert not OutflowTrip.objects.exists()

    def test_a_rule_in_shadow_does_not_latch(self, limits_only):
        from core.models import OutflowTrip

        policy = limits_only.policy
        policy.shadow_rules = ["OutflowBreakerRule"]
        policy.save()

        # Under the AML limit, so that only the breaker has anything to say.
        transfer(limits_only, amount=4_000_000, at=SATURDAY_EVENING_UTC)
        result = transfer(limits_only, amount=4_000_000, at=SATURDAY_EVENING_UTC)

        assert result.should_block is False
        assert [finding["code"] for finding in result.shadow] == ["outflow_limit_exceeded"]
        assert not OutflowTrip.objects.exists()

    def test_shadow_counts_money_because_the_money_really_left(self, limits_only):
        set_enforcement(limits_only, "shadow")
        at = SATURDAY_EVENING_UTC

        transfer(limits_only, amount=7_000_000, at=at)
        result = transfer(limits_only, amount=1_000, at=at)

        assert "outflow_limit_exceeded" in result.factors


class TestUntouchedIntegrations:
    def test_a_policy_without_these_controls_decides_as_before(self, application, no_geoip):
        policy = application.policy
        policy.aml_cft_limit = "NGN 5,000,000.00"
        policy.save()

        result = transfer(application, amount=4_000_000, initiator=None)

        assert "OutflowBreakerRule" not in result.rules
        assert "UnknownBeneficiaryRule" not in result.rules
        assert result.should_block is False

    def test_nothing_is_written_for_them(self, application, no_geoip):
        from core.models import InitiatorBeneficiary

        transfer(application, amount=1_000)

        assert not InitiatorBeneficiary.objects.exists()


class TestOvernightDrainReplay:
    """
    A synthetic reconstruction: two weeks of a partner's normal settlements,
    then overnight transfers of NGN 1-5m from several merchants' accounts to
    new personal accounts at five banks.
    """

    MERCHANTS = ("merchant_a", "merchant_b", "merchant_c")
    BANKS = ("011", "033", "044", "057", "232")

    def settle_normally(self, app, start):
        for day in range(14):
            for merchant in self.MERCHANTS:
                at = start + timedelta(days=day, hours=10)
                transfer(app, client=merchant, beneficiary=f"settle_{merchant}", amount=800_000, at=at)

    def attack(self, app, start):
        """Yields (amount, decision) for each attempted transfer."""
        amounts = (1_000_000, 2_500_000, 5_000_000, 3_000_000, 4_000_000, 1_500_000)
        for index in range(30):
            at = start + timedelta(minutes=20 * index)
            amount = amounts[index % len(amounts)]
            result = transfer(
                app, client=self.MERCHANTS[index % 3], beneficiary=f"mule_{index % 7}",
                bank_code=self.BANKS[index % 5], amount=amount, at=at,
            )
            yield amount, result

    def test_todays_rules_alone_would_have_let_every_transfer_through(self, application, no_geoip):
        policy = application.policy
        policy.aml_cft_limit = "NGN 5,000,000.00"
        policy.save()

        self.settle_normally(application, FRIDAY_NIGHT_UTC - timedelta(days=15))
        decisions = list(self.attack(application, FRIDAY_NIGHT_UTC))

        assert not any(result.should_block for _, result in decisions)

    def test_the_first_transfer_is_refused(self, bank):
        set_enforcement(bank, "shadow")
        self.settle_normally(bank, FRIDAY_NIGHT_UTC - timedelta(days=15))
        set_enforcement(bank, "enforcing")

        decisions = list(self.attack(bank, FRIDAY_NIGHT_UTC))

        assert all(result.should_block for _, result in decisions)
        assert decisions[0][1].should_block is True

    def test_the_breaker_alone_caps_the_loss_at_the_limit(self, limits_only):
        from core.models import OutflowTrip

        decisions = list(self.attack(limits_only, FRIDAY_NIGHT_UTC))
        left = sum(amount for amount, result in decisions if not result.should_block)

        assert left <= LIMITS["per_initiator"]["1h"] * LIMITS["off_hours"]["factor"]
        assert OutflowTrip.objects.filter(scope_kind="initiator", released_at__isnull=True).count() == 1
        assert decisions[-1][1].should_block is True

    def test_for_a_business_that_pays_new_people_the_loss_is_capped_far_lower(self, open_payer):
        set_enforcement(open_payer, "shadow")
        self.settle_normally(open_payer, FRIDAY_NIGHT_UTC - timedelta(days=15))
        set_enforcement(open_payer, "enforcing")

        decisions = list(self.attack(open_payer, FRIDAY_NIGHT_UTC))
        left = sum(amount for amount, result in decisions if not result.should_block)

        assert left <= UNTRUSTED["1h"] * LIMITS["off_hours"]["factor"]
        assert left < LIMITS["per_initiator"]["1h"] * LIMITS["off_hours"]["factor"]

        settlement = transfer(
            open_payer, client="merchant_a", beneficiary="settle_merchant_a", amount=800_000,
            at=FRIDAY_NIGHT_UTC + timedelta(hours=10),
        )
        assert settlement.should_block is False

    def test_normal_settlement_passes_once_enforcing(self, bank):
        set_enforcement(bank, "shadow")
        self.settle_normally(bank, FRIDAY_NIGHT_UTC - timedelta(days=15))
        set_enforcement(bank, "enforcing")

        result = transfer(
            bank, client="merchant_a", beneficiary="settle_merchant_a", amount=800_000,
            at=SATURDAY_EVENING_UTC,
        )

        assert result.should_block is False


class TestUntrustedLimit:
    def test_payments_to_trusted_beneficiaries_do_not_count(self, open_payer):
        trust(open_payer)

        for _ in range(2):
            result = transfer(open_payer, amount=2_000_000, at=SATURDAY_EVENING_UTC)
            assert result.should_block is False
            assert "outflow_limit_exceeded" not in result.factors

    def test_new_beneficiaries_are_reported_and_paid_under_the_limit(self, open_payer):
        result = transfer(open_payer, beneficiary="new_1", amount=2_000_000, at=SATURDAY_EVENING_UTC)

        assert result.should_block is False
        assert "unknown_beneficiary" in [finding["code"] for finding in result.shadow]

    def test_value_to_new_beneficiaries_trips_well_below_the_overall_limit(self, open_payer):
        from core.models import OutflowTrip

        transfer(open_payer, beneficiary="new_1", amount=2_000_000, at=SATURDAY_EVENING_UTC)
        result = transfer(open_payer, beneficiary="new_2", amount=2_000_000, at=SATURDAY_EVENING_UTC)

        assert result.should_block is True
        assert "outflow_limit_exceeded" in result.factors
        trip = OutflowTrip.objects.get(released_at__isnull=True)
        assert (trip.scope_kind, trip.scope_value) == ("initiator_untrusted", PARTNER)

    def test_the_trip_stops_new_payees_and_lets_settlement_carry_on(self, open_payer):
        trust(open_payer)
        transfer(open_payer, beneficiary="new_1", amount=2_000_000, at=SATURDAY_EVENING_UTC)
        transfer(open_payer, beneficiary="new_2", amount=2_000_000, at=SATURDAY_EVENING_UTC)

        known = transfer(open_payer, amount=1_000_000, at=SATURDAY_EVENING_UTC)
        stranger = transfer(open_payer, beneficiary="new_3", amount=1_000, at=SATURDAY_EVENING_UTC)

        assert known.should_block is False
        assert stranger.should_block is True
        assert "outflow_trip_active" in stranger.factors

    def test_a_debit_that_does_not_say_where_it_goes_counts_as_new(self, open_payer):
        transfer(open_payer, beneficiary="new_1", amount=2_000_000, at=SATURDAY_EVENING_UTC)
        result = transfer(open_payer, beneficiary=None, amount=2_000_000, at=SATURDAY_EVENING_UTC)

        assert "outflow_limit_exceeded" in result.factors

    def test_it_learns_payees_without_the_beneficiary_control(self, limits_only):
        policy = limits_only.policy
        policy.outflow_limits = dict(LIMITS, per_initiator_untrusted=UNTRUSTED)
        policy.save()

        transfer(limits_only, beneficiary="payee", amount=100_000, at=SATURDAY_EVENING_UTC)
        later = SATURDAY_EVENING_UTC + timedelta(hours=73)
        for _ in range(2):
            result = transfer(limits_only, beneficiary="payee", amount=2_900_000, at=later)
            assert result.should_block is False

    def test_a_tripped_credential_cannot_age_its_own_payees_into_trust(self, open_payer):
        from core.models import InitiatorBeneficiary

        transfer(open_payer, beneficiary="quiet_mule", amount=1_000_000, at=SATURDAY_EVENING_UTC)
        transfer(open_payer, beneficiary="new_1", amount=1_500_000, at=SATURDAY_EVENING_UTC)
        transfer(open_payer, beneficiary="new_2", amount=1_000_000, at=SATURDAY_EVENING_UTC)

        link = InitiatorBeneficiary.objects.get(beneficiary_key="058:quiet_mule")
        assert link.revoked_at is not None

    def test_a_leaked_key_cannot_raise_it(self, open_payer):
        raised = dict(open_payer.policy.outflow_limits, per_initiator_untrusted={"1h": 90_000_000})
        response = client_as(open_payer).patch(
            f"/api/v1/applications/{open_payer.id}/policy", dict(outflow_limits=raised), format="json",
        )

        assert response.status_code == 403


class TestRelease:
    def tripped(self, app):
        from core.models import OutflowTrip

        transfer(app, amount=7_000_000)
        return OutflowTrip.objects.get(scope_kind="initiator")

    def url(self, app, trip):
        return f"/api/v1/applications/{app.id}/outflow-trips/{trip.id}"

    def test_an_application_key_cannot_release(self, limits_only):
        trip = self.tripped(limits_only)

        response = client_as(limits_only).patch(self.url(limits_only, trip), {}, format="json")

        assert response.status_code == 403
        trip.refresh_from_db()
        assert trip.released_at is None

    def test_a_person_can_and_the_credential_works_from_a_clean_window(self, limits_only):
        trip = self.tripped(limits_only)
        owner = limits_only.organization.owner

        response = client_as(owner).patch(
            self.url(limits_only, trip), dict(note="rotated the key"), format="json",
        )

        assert response.status_code == 200
        trip.refresh_from_db()
        assert trip.released_by == owner
        assert transfer(limits_only, amount=1_000_000).should_block is False

    def test_a_release_is_on_the_audit_chain(self, limits_only):
        from core.models import AuditLog

        trip = self.tripped(limits_only)
        client_as(limits_only.organization.owner).patch(self.url(limits_only, trip), {}, format="json")

        assert AuditLog.objects.filter(action="outflow_released", resource_id=str(trip.id)).exists()

    def test_releasing_twice_is_refused(self, limits_only):
        trip = self.tripped(limits_only)
        client = client_as(limits_only.organization.owner)

        client.patch(self.url(limits_only, trip), {}, format="json")

        assert client.patch(self.url(limits_only, trip), {}, format="json").status_code == 409

    def test_trips_are_listed_and_one_application_cannot_touch_anothers(self, limits_only, second_application):
        trip = self.tripped(limits_only)

        listed = client_as(limits_only).get(f"/api/v1/applications/{limits_only.id}/outflow-trips")
        assert listed.status_code == 200
        assert [row["id"] for row in listed.json()["data"]["trips"]] == [str(trip.id)]

        other = client_as(second_application.organization.owner).patch(
            self.url(second_application, trip), {}, format="json",
        )
        assert other.status_code != 200


class TestAlert:
    def test_a_trip_queues_one_alert(self, limits_only):
        from core.models import WebhookDelivery

        limits_only.webhook_url = "https://bank.example/hooks"
        limits_only.save(update_fields=["webhook_url"])

        with patch("core.outbound.Webhooks.deliver", return_value=None) as deliver:
            at = SATURDAY_EVENING_UTC
            transfer(limits_only, amount=7_000_000, at=at)
            transfer(limits_only, amount=7_000_000, at=at)

        assert WebhookDelivery.objects.filter(event="outflow.tripped").count() == 1
        assert deliver.call_count == 1


class TestALeakedKey:
    def url(self, app):
        return f"/api/v1/applications/{app.id}/policy"

    def patch_as(self, entity, app, body):
        return client_as(entity).patch(self.url(app), body, format="json")

    def raised(self):
        return dict(LIMITS, per_initiator=dict(LIMITS["per_initiator"], **{"1h": 99_000_000}))

    def test_it_cannot_raise_a_limit(self, limits_only):
        assert self.patch_as(limits_only, limits_only, dict(outflow_limits=self.raised())).status_code == 403

    def test_it_cannot_remove_the_limits(self, limits_only):
        assert self.patch_as(limits_only, limits_only, dict(outflow_limits=None)).status_code == 403

    def test_it_cannot_turn_the_beneficiary_control_off(self, bank):
        body = dict(beneficiary_control=dict(enabled=False))
        assert self.patch_as(bank, bank, body).status_code == 403

    def test_it_cannot_shorten_the_cooling_period(self, bank):
        body = dict(beneficiary_control=dict(enabled=True, cooling_hours=1))
        assert self.patch_as(bank, bank, body).status_code == 403

    def test_it_cannot_add_trust(self, bank):
        response = client_as(bank).post(
            f"/api/v1/applications/{bank.id}/trusted-beneficiaries",
            dict(beneficiaries=[dict(initiator_id=PARTNER, client_id="m", counterparty_id="mule")]),
            format="json",
        )

        assert response.status_code == 403

    def test_it_can_tighten(self, limits_only):
        tighter = dict(LIMITS, per_initiator=dict(LIMITS["per_initiator"], **{"1h": 1_000_000}))

        assert self.patch_as(limits_only, limits_only, dict(outflow_limits=tighter)).status_code == 200

    def test_the_owner_can_loosen(self, limits_only):
        owner = limits_only.organization.owner

        assert self.patch_as(owner, limits_only, dict(outflow_limits=self.raised())).status_code == 200

    def test_a_bad_configuration_is_refused(self, application):
        bad = dict(currency="naira", per_initiator={"5m": -1})

        assert self.patch_as(application, application, dict(outflow_limits=bad)).status_code == 400


class TestApprovedBeneficiaries:
    def test_a_person_can_vouch_for_a_list(self, bank):
        response = client_as(bank.organization.owner).post(
            f"/api/v1/applications/{bank.id}/trusted-beneficiaries",
            dict(beneficiaries=[dict(
                initiator_id=PARTNER, client_id="merchant_a",
                counterparty_id="0000000001", counterparty_bank="058",
            )]),
            format="json",
        )

        assert response.status_code == 201
        assert transfer(bank).should_block is False


class TestAuditRateLimit:
    def test_an_application_can_have_its_own_limit(self, application):
        from core.security.middleware import SecurityMiddleware

        application.audit_rate_limit_per_minute = 6000
        application.save(update_fields=["audit_rate_limit_per_minute"])

        assert SecurityMiddleware._audit_config(str(application.id)).requests == 6000

    def test_the_default_stands_otherwise(self, application):
        from core.security.middleware import SecurityMiddleware

        assert SecurityMiddleware._audit_config(str(application.id)) is None
        assert SecurityMiddleware._audit_config("not-a-uuid") is None


class TestThroughTheApi:
    def test_the_initiator_survives_the_real_endpoint(self, limits_only):
        from core.models import AuditLog, OutflowTrip

        body = dict(
            id="tx_api_1", type="debit", amount=4_000_000, currency_code="NGN", client_id="merchant_a",
            counterparty_id="0000000001", counterparty_bank="058", initiator_id=PARTNER, channel="nip",
        )
        client = client_as(limits_only)
        url = f"/api/v1/applications/{limits_only.id}/audit-transaction"

        first = client.post(url, body, format="json")
        second = client.post(url, dict(body, id="tx_api_2"), format="json")

        assert first.status_code == 200, first.content
        assert first.json()["data"]["should_block"] is False
        assert second.json()["data"]["should_block"] is True
        assert OutflowTrip.objects.get().scope_value == PARTNER
        context = AuditLog.objects.get(resource_id="tx_api_1").context
        assert (context["initiator_id"], context["channel"]) == (PARTNER, "nip")

    def test_a_malformed_initiator_is_refused(self, limits_only):
        response = client_as(limits_only).post(
            f"/api/v1/applications/{limits_only.id}/audit-transaction",
            dict(id="tx_api_3", type="debit", amount=1, currency_code="NGN", initiator_id="x" * 129),
            format="json",
        )

        assert response.status_code == 400
