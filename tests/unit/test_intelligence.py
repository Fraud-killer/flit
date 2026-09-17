"""
Unit Tests for FLIT IP and Bot Intelligence

Covers the IP intelligence data sources (GeoIP, Tor and threat lists,
Fingerprint Smart Signals), the IPReputationRule and BotSignalRule, and a
full Auditor.audit run through every registered rule.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


TOR_IP = "185.220.101.1"
CLEAN_IP = "81.2.69.160"  # public, not in any list or fallback range


@pytest.fixture(autouse=True)
def clear_cache():
    from django.core.cache import cache
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def no_geoip():
    from core.intelligence.ip_intelligence import GeoIPDatabase

    previous = GeoIPDatabase._readers
    GeoIPDatabase._readers = {}
    yield
    GeoIPDatabase._readers = previous


class FakeGeoIPReader:
    def __init__(self, asns=None, countries=None):
        self.asns = asns or {}
        self.countries = countries or {}

    def asn(self, ip_address):
        number, organization = self.asns[ip_address]
        return SimpleNamespace(
            autonomous_system_number=number,
            autonomous_system_organization=organization,
        )

    def country(self, ip_address):
        return SimpleNamespace(country=SimpleNamespace(iso_code=self.countries[ip_address]))


@pytest.fixture
def fake_geoip():
    from core.intelligence.ip_intelligence import GeoIPDatabase

    reader = FakeGeoIPReader(
        asns={
            "3.5.140.2": (16509, "AMAZON-02"),
            "5.8.18.1": (12345, "Example Telecom"),
            "91.1.1.1": (9009, "M247 NordVPN Servers"),
        },
        countries={
            "3.5.140.2": "US",
            "5.8.18.1": "RU",
            "91.1.1.1": "DE",
        },
    )
    previous = GeoIPDatabase._readers
    GeoIPDatabase._readers = {"asn": reader, "country": reader}
    yield reader
    GeoIPDatabase._readers = previous


def analyze(ip_address):
    from core.intelligence.ip_intelligence import IPIntelligence
    return asyncio.run(IPIntelligence.analyze(ip_address))


def sample_visit_products(**smart_signals):
    """Trimmed Fingerprint Server API v3 /events/{request_id} `products` payload."""
    products = {
        "identification": {
            "data": {
                "visitorId": "Ibk1527CUFmcnjLwIs4A9",
                "ip": "61.127.217.15",
                "browserDetails": {"userAgent": "Mozilla/5.0 (Macintosh) Chrome/120.0"},
            }
        },
        "ipInfo": {
            "data": {
                "v4": {
                    "address": "61.127.217.15",
                    "geolocation": {
                        "latitude": 37.5,
                        "longitude": 127.0,
                        "city": {"name": "Seoul"},
                        "country": {"code": "KR", "name": "South Korea"},
                        "subdivisions": [{"isoCode": "11", "name": "Seoul"}],
                    },
                    "asn": {"asn": "4766", "name": "Korea Telecom", "network": "61.127.0.0/16"},
                    "datacenter": {"result": False, "name": ""},
                }
            }
        },
    }
    for product, data in smart_signals.items():
        products[product] = {"data": data}
    return products


def make_policy():
    return SimpleNamespace(
        application=SimpleNamespace(id="550e8400-e29b-41d4-a716-446655440000"),
        aml_cft_limit="USD 10,000.00",
        kyc_level_limits={},
    )


def run_rule(rule_class, event, visit=None, visit_error=None):
    from core.audit.scope import Scope

    scope = Scope()
    scope.fetch_visit = AsyncMock(return_value=visit, side_effect=visit_error)
    rule = rule_class(event=event, policy=make_policy(), scope=scope)
    if not rule.applies:
        return []
    return asyncio.run(rule.execute(False))


def codes(messages):
    return [message.code for message in messages]


class TestIPRangeSet:
    def test_matches_single_ips_and_cidrs(self):
        from core.intelligence.ip_intelligence import IPRangeSet

        ranges = IPRangeSet(["1.2.3.4", "10.0.0.0/8", "2001:db8::/32", "not-an-ip"])
        assert "1.2.3.4" in ranges
        assert "1.2.3.5" not in ranges
        assert "10.200.1.1" in ranges
        assert "11.0.0.0" not in ranges
        assert "2001:db8::1" in ranges
        assert "2001:db9::1" not in ranges
        assert "garbage" not in ranges
        assert len(ranges) == 3

    def test_nested_ranges_are_merged(self):
        from core.intelligence.ip_intelligence import IPRangeSet

        ranges = IPRangeSet(["10.0.0.0/8", "10.1.2.0/24", "10.255.0.0/16"])
        assert len(ranges) == 1
        assert "10.1.3.1" in ranges
        assert "10.254.0.1" in ranges

    def test_ipv4_and_ipv6_do_not_collide(self):
        from core.intelligence.ip_intelligence import IPRangeSet

        ranges = IPRangeSet(["0.0.0.1"])
        assert "::1" not in ranges


class TestIPIntelligence:
    def test_private_and_reserved_ips_are_skipped(self, no_geoip):
        from core.intelligence.ip_intelligence import IPIntelligence

        IPIntelligence.TOR_EXIT_NODES.store(["10.0.0.1"])
        info = analyze("10.0.0.1")
        assert not info.is_tor
        assert info.risk_score == 0
        assert IPIntelligence._is_private_ip("not-an-ip")

    def test_flags_tor_exit_node_from_shared_list(self, no_geoip):
        from core.intelligence.ip_intelligence import IPIntelligence

        assert not analyze(TOR_IP).is_tor

        from django.core.cache import cache
        cache.clear()
        IPIntelligence.TOR_EXIT_NODES.store([TOR_IP])

        info = analyze(TOR_IP)
        assert info.is_tor
        assert "tor_exit_node" in info.risk_factors

    def test_flags_ip_inside_threat_list_cidr(self, no_geoip):
        from core.intelligence.ip_intelligence import IPIntelligence

        IPIntelligence.THREAT_LIST.store(["45.155.205.0/24"])
        info = analyze("45.155.205.77")
        assert info.is_known_attacker
        assert "known_attacker" in info.risk_factors

    def test_flags_datacenter_asn_from_geoip(self, fake_geoip):
        info = analyze("3.5.140.2")
        assert info.asn == "AS16509"
        assert info.asn_org == "AMAZON-02"
        assert info.country_code == "US"
        assert info.is_datacenter
        assert "datacenter_ip" in info.risk_factors

    def test_flags_high_risk_country_and_vpn_isp(self, fake_geoip):
        assert "high_risk_country:RU" in analyze("5.8.18.1").risk_factors

        vpn = analyze("91.1.1.1")
        assert vpn.is_vpn
        assert "vpn_detected" in vpn.risk_factors

    def test_falls_back_to_cloud_ranges_without_geoip(self, no_geoip):
        info = analyze("54.217.46.204")
        assert info.is_datacenter
        assert not analyze(CLEAN_IP).is_datacenter

    def test_refresh_stores_list_without_comments(self, no_geoip):
        from core.intelligence.ip_intelligence import IPIntelligence

        response = MagicMock(text="# Tor exit list\n185.220.101.1\n\n185.220.101.2\n")
        with patch("core.intelligence.ip_intelligence.requests.get", return_value=response) as get:
            assert IPIntelligence.refresh_tor_exit_nodes() == 2

        get.assert_called_once_with(IPIntelligence.TOR_EXIT_LIST_URL, timeout=IPIntelligence.REQUEST_TIMEOUT_SECONDS)
        assert "185.220.101.2" in IPIntelligence.TOR_EXIT_NODES

    def test_refresh_command_reports_failures(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError

        with patch(
            "core.intelligence.ip_intelligence.requests.get",
            side_effect=ConnectionError("offline"),
        ):
            with pytest.raises(CommandError, match="offline"):
                call_command("refresh_threat_intel")


class TestFingerprintSmartSignals:
    def test_normalizes_smart_signals(self):
        from core.services.fingerprint import FetchVisitData

        visit = FetchVisitData.normalize_visit_data(sample_visit_products(
            vpn={"result": True},
            proxy={"result": False},
            tor={"result": False},
            ipBlocklist={"result": True},
            incognito={"result": True},
            botd={"bot": {"result": "bad", "type": "selenium"}},
        ))

        assert visit.fingerprint == "Ibk1527CUFmcnjLwIs4A9"
        assert visit.country == "South Korea"
        assert visit.ip == "61.127.217.15"
        assert visit.user_agent.startswith("Mozilla/5.0")
        assert visit.asn == "4766"
        assert visit.asn_org == "Korea Telecom"
        assert visit.is_datacenter is False
        assert visit.vpn is True
        assert visit.proxy is False
        assert visit.ip_blocklisted is True
        assert visit.incognito is True
        assert visit.bot == "bad"

    def test_missing_smart_signals_are_none(self):
        from core.services.fingerprint import FetchVisitData

        visit = FetchVisitData.normalize_visit_data(sample_visit_products())
        assert visit.vpn is None
        assert visit.tor is None
        assert visit.bot is None


class TestIPReputationRule:
    def test_flags_tor_ip_from_event(self, no_geoip):
        from core.audit.events import TransactionEvent
        from core.audit.rules import IPReputationRule
        from core.intelligence.ip_intelligence import IPIntelligence

        IPIntelligence.TOR_EXIT_NODES.store([TOR_IP])
        event = TransactionEvent(id="tx_1", type="debit", ip_address=TOR_IP)

        messages = run_rule(IPReputationRule, event)
        assert codes(messages) == ["tor_exit_node"]
        assert messages[0].context["sources"] == ["local"]
        assert messages[0].context["ip_address"] == TOR_IP

    def test_uses_visit_ip_and_smart_signals(self, no_geoip):
        from core.audit.events import ClientEvent
        from core.audit.rules import IPReputationRule

        visit = SimpleNamespace(ip=CLEAN_IP, vpn=True, proxy=False, tor=None, asn="4766")
        event = ClientEvent(id="client_1", visit_id="visit_1")

        messages = run_rule(IPReputationRule, event, visit=visit)
        assert codes(messages) == ["vpn_detected"]
        assert messages[0].context["sources"] == ["fingerprint"]
        assert messages[0].context["ip_address"] == CLEAN_IP

    def test_fingerprint_outage_does_not_fail_the_rule(self, no_geoip):
        from core.audit.events import TransactionEvent
        from core.audit.rules import IPReputationRule

        event = TransactionEvent(
            id="tx_1",
            type="debit",
            visit_id="visit_1",
            ip_address="54.217.46.204",
        )
        messages = run_rule(IPReputationRule, event, visit_error=RuntimeError("401"))
        assert codes(messages) == ["datacenter_ip"]

    def test_clean_ip_has_no_findings(self, no_geoip):
        from core.audit.events import TransactionEvent
        from core.audit.rules import IPReputationRule

        event = TransactionEvent(id="tx_1", type="debit", ip_address=CLEAN_IP)
        assert run_rule(IPReputationRule, event) == []

    def test_does_not_apply_without_ip_or_visit(self):
        from core.audit.events import TransactionEvent
        from core.audit.rules import IPReputationRule

        assert run_rule(IPReputationRule, TransactionEvent(id="tx_1", type="debit")) == []


class TestBotSignalRule:
    def test_flags_automated_user_agent(self):
        from core.audit.events import TransactionEvent
        from core.audit.rules import BotSignalRule

        event = TransactionEvent(id="tx_1", type="debit", user_agent="curl/7.68.0")
        messages = run_rule(BotSignalRule, event)
        assert codes(messages) == ["bot_detected:http_client"]
        assert messages[0].context["score"] >= 0.9

    def test_allows_search_crawlers_and_browsers(self):
        from core.audit.events import TransactionEvent
        from core.audit.rules import BotSignalRule

        for user_agent in (
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        ):
            event = TransactionEvent(id="tx_1", type="debit", user_agent=user_agent)
            assert run_rule(BotSignalRule, event) == [], user_agent

    def test_flags_fingerprint_bad_bot(self):
        from core.audit.events import ClientEvent
        from core.audit.rules import BotSignalRule

        visit = SimpleNamespace(bot="bad", user_agent="Mozilla/5.0 Chrome/120.0")
        event = ClientEvent(id="client_1", visit_id="visit_1")
        assert codes(run_rule(BotSignalRule, event, visit=visit)) == ["bot_detected:fingerprint"]


class TestEventNetworkAttributes:
    def test_rejects_invalid_ip_address(self):
        from core.audit.events import ClientEvent

        errors = ClientEvent(id="client_1", ip_address="999.1.1.1", user_agent="").verify()
        assert {(e.code, e.path) for e in errors} == {
            ("void_or_ip_address", "ip_address"),
            ("void_or_dense_string", "user_agent"),
        }

    def test_accepts_ipv4_and_ipv6(self):
        from core.audit.events import ClientEvent

        for ip_address in ("8.8.8.8", "2001:4860:4860::8888"):
            assert ClientEvent(id="client_1", ip_address=ip_address).verify() == []


class TestAuditorEndToEnd:
    """Regression test: every registered rule must run inside Auditor.audit."""

    def audit(self, **attributes):
        from core.audit.auditor import Auditor
        from core.audit.events import TransactionEvent

        event = TransactionEvent(id="tx_1", type="debit", amount=25, currency_code="USD", **attributes)
        return asyncio.run(Auditor.audit(
            event,
            make_policy(),
            send_alerts=False,
            include_historical=False,
        ))

    def test_intelligence_signals_raise_the_risk_score(self, no_geoip):
        from core.intelligence.ip_intelligence import IPIntelligence

        IPIntelligence.TOR_EXIT_NODES.store([TOR_IP])

        clean = self.audit(
            ip_address=CLEAN_IP,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        )

        from django.core.cache import cache
        cache.delete(IPIntelligence.get_cache_key(TOR_IP))

        risky = self.audit(
            ip_address=TOR_IP,
            user_agent="curl/7.68.0",
            status="failed",
            gateway_message="Declined by Acquirer: Anti-fraud",
        )

        assert "IPReputationRule" in risky.rules
        assert "BotSignalRule" in risky.rules
        assert "tor_exit_node" in risky.factors
        assert "bot_detected:http_client" in risky.factors
        assert "gateway_issuer_fraud" in risky.factors
        assert "tor_exit_node" not in clean.factors
        assert risky.risk_score > clean.risk_score
        assert risky.risk_level in ("high", "critical")
