"""
Tests for the signup surface: the identity ladder, email intelligence, and
absence-as-evidence.

The centrepiece is a replay of a real attack. On 19 September 2026 a single
actor registered eleven accounts against a live card issuer in eighty minutes
— all from one IP, all with `curl/8.20.0`, all on throwaway or reserved
domains, several named after the unix clock. FLIT's rules at the time scored
it as eleven ordinary signups, because every rule that would have correlated
them was gated behind a device fingerprint the attacker never produced.

Each behaviour is checked twice: that it fires on the attack, and that the
ordinary customer doing a similar-looking thing does not trip it.
"""

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, patch

from django.utils import timezone


ATTACKER_IP = "193.200.229.243"
CURL = "curl/8.20.0"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"


# The eleven accounts, in the order they were created.
ATTACK_SIGNUPS = [
    ("pentest.figo+1@wearehackerone.com", "NG"),
    ("pentest.figo+ma@wearehackerone.com", "NG"),
    ("pt17898419844892@example.com", "US"),
    ("pentest.figo+142358@wearehackerone.com", "US"),
    ("figo11409@uberip.com", "US"),
    ("probe_flow_test@example.com", "US"),
    ("figopentest563d42fd@uberip.com", "NG"),
    ("figob17983133@uberip.com", "US"),
    ("newinvite1789843214@uberip.com", "US"),
    ("figomass1789844680@uberip.com", "US"),
    ("figomass1789844685@uberip.com", "US"),
]


def make_visit(visitor_id="visitor_1", user_agent=BROWSER, ip="81.2.69.160"):
    from devkit.struct import Struct

    return Struct(
        raw_data={}, fingerprint=visitor_id, city="Lagos", state="Lagos",
        country="Nigeria", latitude=6.5, longitude=3.3, ip=ip,
        user_agent=user_agent, asn="AS4766", asn_org="Example Telecom",
        is_datacenter=False, vpn=False, proxy=False, tor=False,
        ip_blocklisted=False, incognito=False, bot="notDetected",
        device_signals={}, suspect_score=0,
    )


def register(application, *, email, ip_address, user_agent, visit=None,
             country="US", client_id=None, visit_id=None):
    """One signup, audited the way a merchant's registration endpoint would."""
    from core.audit.auditor import Auditor
    from core.audit.events import RegistrationEvent

    event = RegistrationEvent(
        id=client_id or email,
        client_id=client_id or email,
        email=email,
        country=country,
        ip_address=ip_address,
        user_agent=user_agent,
        visit_id=visit_id,
        action="registration",
    )

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=visit),
    ):
        return asyncio.run(
            Auditor.audit(event, application.policy, send_alerts=False)
        )


def codes(result):
    return list(result.factors)


class TestEmailIntelligence:
    def test_collapses_plus_tags_to_one_mailbox(self):
        from core.intelligence.email_intelligence import normalize_email

        roots = {
            normalize_email("pentest.figo+1@wearehackerone.com"),
            normalize_email("pentest.figo+ma@wearehackerone.com"),
            normalize_email("pentest.figo+142358@wearehackerone.com"),
        }

        assert roots == {"pentest.figo@wearehackerone.com"}

    def test_collapses_gmail_dots_but_not_other_providers(self):
        from core.intelligence.email_intelligence import normalize_email

        assert normalize_email("j.o.h.n@gmail.com") == "john@gmail.com"
        # Everyone else treats dots as significant, so collapsing them would
        # merge two real, distinct users.
        assert normalize_email("j.o.h.n@fastmail.com") == "j.o.h.n@fastmail.com"

    def test_reads_a_unix_timestamp_out_of_the_local_part(self):
        from core.intelligence.email_intelligence import analyze

        first = analyze("figomass1789844680@uberip.com")
        second = analyze("figomass1789844685@uberip.com")

        assert first.has_epoch_local and second.has_epoch_local
        # Five seconds apart: a generator, not two people.
        assert second.epoch_value - first.epoch_value == 5

    def test_leaves_an_ordinary_address_alone(self):
        from core.intelligence.email_intelligence import analyze

        analysis = analyze("adebayo.okafor@gmail.com")

        assert analysis.valid
        assert not analysis.is_disposable
        assert not analysis.has_epoch_local
        assert not analysis.machine_generated
        assert analysis.signals == []

    def test_a_year_in_a_name_is_not_a_timestamp(self):
        from core.intelligence.email_intelligence import analyze

        # Real people put birth years and phone numbers in addresses.
        for address in ("tunde1992@gmail.com", "chidi08031234567@yahoo.com"):
            assert not analyze(address).has_epoch_local

    def test_redaction_never_reveals_the_mailbox(self):
        from core.intelligence.email_intelligence import redact

        assert redact("adebayo.okafor@gmail.com") == "a***@gmail.com"

    def test_flags_disposable_and_reserved_domains(self):
        from core.intelligence.email_intelligence import (
            is_disposable_domain, is_reserved_domain,
        )

        assert is_disposable_domain("uberip.com")
        assert is_disposable_domain("some-tempmail-clone.net")
        assert is_reserved_domain("example.com")
        assert not is_disposable_domain("gmail.com")
        assert not is_reserved_domain("gmail.com")


class TestIdentityLadder:
    def test_falls_back_to_the_ip_when_there_is_no_device(self, application, no_geoip):
        """
        The rule that matters most. AccountFarmingRule used to require a
        device identity, so an attacker who never ran the JavaScript switched
        it off — and that is precisely the attacker worth catching.
        """
        result = None

        for index in range(10):
            result = register(
                application,
                email=f"farm{index}@uberip.com",
                ip_address=ATTACKER_IP,
                user_agent=CURL,
                client_id=f"farmed_{index}",
            )

        assert "account_farming:ip" in codes(result)

    def test_names_the_key_so_a_reviewer_knows_what_it_rests_on(
        self, application, no_geoip,
    ):
        result = None

        for index in range(10):
            result = register(
                application,
                email=f"farm{index}@uberip.com",
                ip_address=ATTACKER_IP,
                user_agent=CURL,
                client_id=f"farmed_{index}",
            )

        message = next(m for m in result.reasons if m.code == "account_farming:ip")

        assert message.context["key_type"] == "ip"
        assert message.context["key_confidence"] == 0.5
        # The ladder's strongest rung here is the email root, which is not
        # what breached: every address was distinct, so only the shared IP
        # correlates them. The finding names the key it actually rests on.
        assert result.identity["strongest"] == "email_root"
        assert "ip" in result.identity["rungs"]

    def test_an_ip_finding_is_worth_less_than_a_device_finding(self):
        from core.scoring.weights import DEFAULT_WEIGHTS

        device = DEFAULT_WEIGHTS.get_weight("account_farming")
        ip = DEFAULT_WEIGHTS.get_weight("account_farming:ip")

        assert ip < device
        assert ip == round(device * 0.5, 4)

    def test_a_device_finding_keeps_its_historical_code(self, application, no_geoip):
        """Merchant dashboards and weight overrides are keyed on the bare code."""
        visit = make_visit()
        result = None

        for index in range(5):
            result = register(
                application,
                email=f"house{index}@gmail.com",
                ip_address="81.2.69.160",
                user_agent=BROWSER,
                visit=visit,
                visit_id="v1",
                client_id=f"household_{index}",
            )

        assert "account_farming" in codes(result)
        assert "account_farming:device" not in codes(result)

    def test_several_plus_tags_resolve_to_one_mailbox(self, application, no_geoip):
        """
        Three of the real signups differed only by plus-tag. Collapsed, they
        are one mailbox creating accounts in bulk.
        """
        result = None

        for index in range(4):
            result = register(
                application,
                email=f"pentest.figo+{index}@wearehackerone.com",
                # Distinct IPs, so only the email root can correlate them.
                ip_address=f"198.51.100.{index + 1}",
                user_agent=CURL,
                client_id=f"tagged_{index}",
            )

        assert "account_farming:email_root" in codes(result)

    def test_a_merchant_can_retune_one_key_without_restating_the_rest(
        self, application, no_geoip,
    ):
        policy = application.policy
        policy.identity_thresholds = {"new_accounts_per_day": {"ip": 2}}
        policy.save()

        result = None
        for index in range(4):
            result = register(
                application,
                email=f"tuned{index}@gmail.com",
                ip_address="203.0.113.9",
                user_agent=BROWSER,
                client_id=f"tuned_{index}",
            )

        # The tightened IP limit bites...
        assert "account_farming:ip" in codes(result)

        # ...and the keys left alone keep their defaults.
        from core.audit.rules.identity_thresholds import get_identity_thresholds

        thresholds = get_identity_thresholds(policy)
        assert thresholds["new_accounts_per_day"]["ip"] == 2
        assert thresholds["new_accounts_per_day"]["email_root"] == 2
        assert thresholds["max_accounts"]["ip"] == 15

    def test_legacy_device_policy_fields_are_still_honoured(self, application):
        """A merchant who tuned the pre-ladder fields keeps what they set."""
        from core.audit.rules.identity_thresholds import get_identity_thresholds

        policy = application.policy
        policy.mule_thresholds = {"new_accounts_per_device_per_day": 9}
        policy.device_thresholds = {"max_accounts_per_device": 7}
        policy.save()

        thresholds = get_identity_thresholds(policy)

        assert thresholds["new_accounts_per_day"]["device"] == 9
        assert thresholds["max_accounts"]["device"] == 7

    def test_does_not_count_accounts_on_an_asn(self, application, no_geoip):
        """
        A consumer ISP's ASN carries every real signup in a market. Counting
        on it would flag an entire country.
        """
        from core.audit.rules.identity_thresholds import NON_CORRELATING_KEYS
        from core.identity_keys import IdentityKeyType

        assert IdentityKeyType.ASN in NON_CORRELATING_KEYS

    def test_carrier_grade_nat_does_not_trip_the_ip_rung(
        self, application, no_geoip,
    ):
        """
        A whole mobile market can sit behind one address. Six real signups
        from one IP must stay quiet.
        """
        result = None

        for index in range(6):
            result = register(
                application,
                email=f"real.person{index}@gmail.com",
                ip_address="102.89.23.14",
                user_agent=BROWSER,
                visit=make_visit(visitor_id=f"visitor_{index}", ip="102.89.23.14"),
                visit_id=f"v{index}",
                client_id=f"mtn_user_{index}",
            )

        assert "account_farming:ip" not in codes(result)
        assert not result.should_block
        assert not result.should_challenge


class TestAbsenceAsEvidence:
    def seed_baseline(self, application, *, with_device, total=60):
        """Give the application a history of device-bearing traffic."""
        from core.models import AuditLog

        for index in range(total):
            AuditLog.objects.create(
                level="info",
                category="security",
                action="registration",
                actor_id=f"seed_{index}",
                application_id=application.id,
                device_fingerprint=f"fp_{index}" if index < with_device else None,
                timestamp=timezone.now() - timedelta(hours=1),
            )

    def clear_baseline_cache(self, application):
        from django.core.cache import cache

        cache.delete(f"flit:device_baseline:{application.id}")

    def test_flags_an_event_that_produced_no_device_key(
        self, application, no_geoip,
    ):
        self.seed_baseline(application, with_device=57)   # 95% of traffic
        self.clear_baseline_cache(application)

        result = register(
            application,
            email="quiet@uberip.com",
            ip_address=ATTACKER_IP,
            user_agent=CURL,
            client_id="silent_1",
        )

        assert "missing_expected_device_signal" in codes(result)

    def test_stays_quiet_for_a_merchant_who_has_not_deployed_collection(
        self, application, no_geoip,
    ):
        """
        A merchant still integrating must never be punished for it, or the
        rule becomes a false-positive engine on day one.
        """
        self.seed_baseline(application, with_device=3)    # 5% of traffic
        self.clear_baseline_cache(application)

        result = register(
            application,
            email="early.adopter@gmail.com",
            ip_address="81.2.69.160",
            user_agent=BROWSER,
            client_id="integrating_1",
        )

        assert "missing_expected_device_signal" not in codes(result)

    def test_stays_quiet_without_enough_history_to_judge(
        self, application, no_geoip,
    ):
        self.seed_baseline(application, with_device=10, total=10)
        self.clear_baseline_cache(application)

        result = register(
            application,
            email="brand.new@gmail.com",
            ip_address="81.2.69.160",
            user_agent=BROWSER,
            client_id="new_1",
        )

        assert "missing_expected_device_signal" not in codes(result)

    def test_coverage_reports_how_much_signal_arrived(
        self, application, no_geoip,
    ):
        thin = register(
            application,
            email="thin@uberip.com",
            ip_address=ATTACKER_IP,
            user_agent=CURL,
            client_id="thin_1",
        )

        rich = register(
            application,
            email="rich@gmail.com",
            ip_address="81.2.69.160",
            user_agent=BROWSER,
            visit=make_visit(),
            visit_id="v1",
            client_id="rich_1",
        )

        # Below 0.5 means the device key is missing; above it, present.
        assert thin.coverage < 0.5 < rich.coverage


class TestChallengeOutcome:
    def test_challenge_sits_below_block(self):
        from core.scoring.weights import DEFAULT_THRESHOLDS

        assert (
            DEFAULT_THRESHOLDS.challenge_at < DEFAULT_THRESHOLDS.block_at
        )

    def test_a_blocked_decision_is_not_also_challenged(self):
        from core.scoring import RiskEngine

        result = RiskEngine().calculate_risk(
            [
                {"code": "account_takeover_risk", "text": "", "context": {}},
                {"code": "known_attacker", "text": "", "context": {}},
            ],
            event_category="registration",
        )

        assert result.should_block
        assert not result.should_challenge

    def test_severity_grades_a_finding_without_changing_its_weight(self):
        from core.scoring import RiskEngine

        engine = RiskEngine()

        mild = engine.calculate_risk(
            [{"code": "disposable_email_domain", "text": "", "context": {"severity": 0.2}}],
            event_category="registration",
        )
        severe = engine.calculate_risk(
            [{"code": "disposable_email_domain", "text": "", "context": {"severity": 0.9}}],
            event_category="registration",
        )

        assert severe.total_score > mild.total_score
        # The kind of evidence is unchanged; only this instance's severity is.
        assert mild.factors[0].weight == severe.factors[0].weight

    def test_a_rule_without_a_severity_is_taken_at_full_strength(self):
        """Every rule written before severity existed must score as it did."""
        from core.scoring import RiskEngine

        result = RiskEngine().calculate_risk(
            [{"code": "tor_exit_node", "text": "", "context": {}}],
            event_category="transaction",
        )

        assert result.factors[0].score == 1.0


class TestSeptember2026Replay:
    """
    The attack that prompted all of this, replayed end to end.

    Ground truth: every one of these eleven accounts was hostile, and FLIT as
    it stood scored them as ordinary signups.
    """

    def replay(self, application):
        results = []

        for index, (email, country) in enumerate(ATTACK_SIGNUPS):
            results.append(
                register(
                    application,
                    email=email,
                    country=country,
                    ip_address=ATTACKER_IP,
                    user_agent=CURL,
                    client_id=f"attack_{index}",
                )
            )

        return results

    def test_the_bare_http_client_is_caught_immediately(
        self, application, no_geoip,
    ):
        results = self.replay(application)

        assert "bot_detected:http_client" in codes(results[0])

    def test_the_throwaway_and_reserved_domains_are_caught(
        self, application, no_geoip,
    ):
        results = self.replay(application)
        every_code = {code for result in results for code in codes(result)}

        assert "disposable_email_domain" in every_code
        assert "reserved_email_domain" in every_code

    def test_the_generated_addresses_are_caught(self, application, no_geoip):
        results = self.replay(application)
        every_code = {code for result in results for code in codes(result)}

        assert "generated_email_local_part" in every_code
        assert "adversarial_email_local_part" in every_code

    def test_the_flood_is_correlated_without_any_device(
        self, application, no_geoip,
    ):
        results = self.replay(application)

        # No device fingerprint was ever produced, so the whole device graph
        # is blind here. The ladder is what sees it.
        assert all(result.device_id is None for result in results)
        assert "account_farming:ip" in codes(results[-1])

    def test_the_attack_escalates_to_a_challenge_or_worse(
        self, application, no_geoip,
    ):
        results = self.replay(application)
        stopped = [
            result for result in results
            if result.should_challenge or result.should_block
        ]

        # Not merely detected — acted on, and on most of the flood.
        assert len(stopped) >= 8

    def test_ordinary_signups_in_the_same_window_are_untouched(
        self, application, no_geoip,
    ):
        """
        The control. Real users signed up throughout the same afternoon from
        Kenya, Zambia, Uganda and Morocco. If they are challenged too, the
        defence is worthless.
        """
        self.replay(application)

        legitimate = [
            ("mugidenis3@gmail.com", "KE", "105.160.1.20"),
            ("christian.chanda@protonmail.com", "ZM", "102.23.14.9"),
            ("jerm78336@gmail.com", "UG", "41.210.180.4"),
            ("elouihyaouibrahim@gmail.com", "MA", "105.157.22.31"),
        ]

        for index, (email, country, ip) in enumerate(legitimate):
            result = register(
                application,
                email=email,
                country=country,
                ip_address=ip,
                user_agent=BROWSER,
                visit=make_visit(visitor_id=f"real_visitor_{index}", ip=ip),
                visit_id=f"real_v{index}",
                client_id=f"real_{index}",
            )

            assert not result.should_block, f"{email} was blocked"
            assert not result.should_challenge, f"{email} was challenged"
