"""
Tests for domain intelligence.

Two questions the local email heuristics cannot answer: can this address
receive mail at all, and how long has its domain existed? Both are answered
over the network, so the tests care as much about what happens when the
network is unavailable as about what happens when it answers.

Nothing here touches the real internet. Lookups are disabled suite-wide in
conftest and re-enabled here against stubs.
"""

import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as datetime_timezone
from unittest.mock import AsyncMock, patch

from tests.unit.test_signup_defence import BROWSER, codes, register


@contextmanager
def lookups(*, mx=None, registered_at=None, mx_error=None, rdap_error=None):
    """Turn lookups on with stubbed answers. `None` means "unknown"."""
    from core.intelligence.domain_intelligence import DomainIntelligence

    with patch.object(DomainIntelligence, "enabled", classmethod(lambda cls: True)), \
         patch(
             "core.intelligence.domain_intelligence._mx_records",
             AsyncMock(return_value=mx, side_effect=mx_error),
         ), \
         patch(
             "core.intelligence.domain_intelligence._registration_date",
             AsyncMock(return_value=registered_at, side_effect=rdap_error),
         ):
        yield


def analyze(domain, **kwargs):
    from core.intelligence.domain_intelligence import DomainIntelligence

    with lookups(**kwargs):
        return asyncio.run(DomainIntelligence.analyze(domain))


def days_ago(days):
    return datetime.now(datetime_timezone.utc) - timedelta(days=days)


class TestDomainLookups:
    def test_an_established_provider_is_never_looked_up(self):
        """
        Most honest signups are on a handful of providers. Skipping them
        saves the request and means a DNS outage cannot touch the majority
        of real users.
        """
        info = analyze("gmail.com", mx=[])

        assert info.established
        assert info.has_mx is True
        # The stub said no MX; it was never consulted.
        assert info.checked is False

    def test_a_domain_with_no_mx_records_is_identified(self, mock_cache):
        info = analyze("not-a-real-mail-domain.xyz", mx=[])

        assert info.has_mx is False
        assert info.cannot_receive_mail

    def test_a_domain_with_mx_records_is_fine(self, mock_cache):
        info = analyze("realbusiness.co", mx=["mx1.realbusiness.co"])

        assert info.has_mx is True
        assert not info.cannot_receive_mail

    def test_a_fresh_registration_is_identified(self, mock_cache):
        info = analyze(
            "registered-yesterday.com",
            mx=["mx.registered-yesterday.com"],
            registered_at=days_ago(3),
        )

        assert info.age_days == 3
        assert info.is_newly_registered

    def test_an_old_domain_is_not(self, mock_cache):
        info = analyze(
            "established.com", mx=["mx.established.com"],
            registered_at=days_ago(4000),
        )

        assert not info.is_newly_registered

    def test_an_unreachable_resolver_reads_as_unknown(self, mock_cache):
        """
        The important one. A failed lookup must not read as "clean" or as
        "suspicious" — both would be inventing evidence.
        """
        info = analyze(
            "unknown.com",
            mx_error=OSError("dns down"),
            rdap_error=OSError("rdap down"),
        )

        assert info.has_mx is None
        assert info.age_days is None
        assert not info.cannot_receive_mail
        assert not info.is_newly_registered

    def test_lookups_stay_off_when_disabled(self):
        from core.intelligence.domain_intelligence import DomainIntelligence

        # conftest disables them for the whole suite; this asserts the switch
        # actually gates the call rather than merely existing.
        with patch(
            "core.intelligence.domain_intelligence._mx_records",
            AsyncMock(return_value=[]),
        ) as mx:
            info = asyncio.run(DomainIntelligence.analyze("somewhere.test"))

        assert info.checked is False
        mx.assert_not_called()


class TestDomainReputationRule:
    def test_flags_an_address_that_cannot_receive_mail(
        self, application, no_geoip, mock_cache,
    ):
        with lookups(mx=[]):
            result = register(
                application,
                email="someone@no-mx-anywhere.co",
                ip_address="81.2.69.160",
                user_agent=BROWSER,
                client_id="nomx_1",
            )

        assert "domain_cannot_receive_mail" in codes(result)

    def test_flags_a_domain_registered_days_ago(
        self, application, no_geoip, mock_cache,
    ):
        with lookups(mx=["mx.brand-new.co"], registered_at=days_ago(2)):
            result = register(
                application,
                email="founder@brand-new.co",
                ip_address="81.2.69.160",
                user_agent=BROWSER,
                client_id="new_domain_1",
            )

        assert "newly_registered_domain" in codes(result)

    def test_says_nothing_when_the_lookup_failed(
        self, application, no_geoip, mock_cache,
    ):
        with lookups(mx_error=OSError("dns down"), rdap_error=OSError("down")):
            result = register(
                application,
                email="someone@unreachable.co",
                ip_address="81.2.69.160",
                user_agent=BROWSER,
                client_id="unknown_1",
            )

        assert "domain_cannot_receive_mail" not in codes(result)
        assert "newly_registered_domain" not in codes(result)

    def test_does_not_score_a_disposable_domain_twice(
        self, application, no_geoip, mock_cache,
    ):
        """DisposableEmailRule already owns that finding."""
        with lookups(mx=[], registered_at=days_ago(1)):
            result = register(
                application,
                email="someone@uberip.com",
                ip_address="81.2.69.160",
                user_agent=BROWSER,
                client_id="double_1",
            )

        assert "disposable_email_domain" in codes(result)
        assert "domain_cannot_receive_mail" not in codes(result)
        assert "newly_registered_domain" not in codes(result)

    def test_an_ordinary_provider_is_untouched(
        self, application, no_geoip, mock_cache,
    ):
        with lookups(mx=[], registered_at=days_ago(1)):
            result = register(
                application,
                email="real.person@gmail.com",
                ip_address="81.2.69.160",
                user_agent=BROWSER,
                client_id="ordinary_1",
            )

        assert "domain_cannot_receive_mail" not in codes(result)
        assert "newly_registered_domain" not in codes(result)
        assert not result.should_block
        assert not result.should_challenge
