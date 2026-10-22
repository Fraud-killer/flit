"""
Tests for OFAC sanctions screening.

Two things get equal care here: that a listed address is caught, and that a
list which failed to load is *visible*. A compliance check that quietly does
nothing is worse than one that is absent, because it looks like coverage.

Nothing here reaches Treasury: the document is a fixture shaped like the real
SDN XML, and the download is stubbed.
"""

from unittest.mock import MagicMock, patch

import pytest

from tests.unit.test_crypto import codes, transfer


# Shaped like the real SDN XML, including the pretty-printing between tags.
SDN_DOCUMENT = """<?xml version="1.0" encoding="UTF-8"?>
<sdnList>
  <sdnEntry>
    <uid>12345</uid>
    <lastName>SOME ENTITY</lastName>
    <idList>
      <id>
        <uid>901</uid>
        <idType>Digital Currency Address - ETH</idType>
        <idNumber>0x7F367cC41522cE07553e823bf3be79A889DEbe1B</idNumber>
      </id>
      <id>
        <uid>902</uid>
        <idType>Digital Currency Address - XBT</idType>
        <idNumber>1DUb2YYbQA1jjaNYzVXLZ7ZioEhLXtbUru</idNumber>
      </id>
      <id>
        <uid>903</uid>
        <idType>Passport</idType>
        <idNumber>X1234567</idNumber>
      </id>
    </idList>
  </sdnEntry>
</sdnList>
"""

LISTED_EVM = "0x7F367cC41522cE07553e823bf3be79A889DEbe1B"
LISTED_BTC = "1DUb2YYbQA1jjaNYzVXLZ7ZioEhLXtbUru"
CLEAN_EVM = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


@pytest.fixture(autouse=True)
def reset_list():
    """The list is cached in Django and again per process; clear both."""
    from django.core.cache import cache
    from core.intelligence.sanctions import SanctionsList

    def clear():
        cache.clear()
        SanctionsList._version = None
        SanctionsList._addresses = frozenset()

    clear()
    yield
    clear()


def load(document=SDN_DOCUMENT):
    from core.intelligence.sanctions import SanctionsList

    response = MagicMock(text=document)
    response.raise_for_status = MagicMock()

    with patch("core.intelligence.sanctions.requests.get", return_value=response):
        return SanctionsList.refresh("https://example.test/sdn.xml")


class TestParsing:
    def test_digital_currency_addresses_are_extracted(self):
        from core.intelligence.sanctions import SanctionsList

        addresses = SanctionsList.parse(SDN_DOCUMENT)

        assert LISTED_EVM.lower() in addresses
        assert LISTED_BTC in addresses

    def test_other_identifiers_are_ignored(self):
        from core.intelligence.sanctions import SanctionsList

        assert SanctionsList.parse(SDN_DOCUMENT) == {
            LISTED_EVM.lower(), LISTED_BTC,
        }

    def test_evm_case_is_normalised_but_bitcoin_is_not(self):
        """Only EVM addresses are case-insensitive; lowercasing a Bitcoin
        address would break the comparison."""
        from core.intelligence.sanctions import screening_key

        assert screening_key(LISTED_EVM) == LISTED_EVM.lower()
        assert screening_key(LISTED_BTC) == LISTED_BTC


class TestTheList:
    def test_a_listed_address_is_matched_in_any_case(self):
        from core.intelligence.sanctions import SanctionsList

        assert load() == 2
        assert SanctionsList.contains(LISTED_EVM)
        assert SanctionsList.contains(LISTED_EVM.lower())
        assert SanctionsList.contains(LISTED_EVM.upper().replace("0X", "0x"))

    def test_an_unlisted_address_is_not(self):
        from core.intelligence.sanctions import SanctionsList

        load()
        assert not SanctionsList.contains(CLEAN_EVM)

    def test_an_empty_download_does_not_overwrite_the_loaded_list(self):
        """
        A changed format or a truncated download must not silently empty the
        list — that is how screening stops happening without anyone noticing.
        """
        from core.intelligence.sanctions import SanctionsList

        load()

        with pytest.raises(ValueError):
            load("<sdnList></sdnList>")

        assert SanctionsList.contains(LISTED_EVM)

    def test_status_reports_what_is_loaded(self):
        from core.intelligence.sanctions import SanctionsList

        assert SanctionsList.status()["loaded"] is False

        load()
        status = SanctionsList.status()

        assert status["loaded"] is True
        assert status["count"] == 2
        assert status["stale"] is False


class TestSanctionedAddressRule:
    def test_a_listed_counterparty_is_flagged_and_blocks(
        self, application, no_geoip,
    ):
        load()
        result = transfer(
            application, type="debit", client_id="payer_1",
            counterparty_address=LISTED_EVM,
        )

        assert "sanctioned_address" in codes(result)
        assert result.should_block

    def test_a_clean_counterparty_is_not(self, application, no_geoip):
        load()
        result = transfer(
            application, type="debit", client_id="payer_2",
            counterparty_address=CLEAN_EVM,
        )

        assert "sanctioned_address" not in codes(result)
        assert not result.should_block

    def test_an_unloaded_list_is_reported_rather_than_passing_silently(
        self, application, no_geoip,
    ):
        """The failure mode that matters. Nothing is loaded, so nothing was
        screened, and the decision has to say so."""
        result = transfer(
            application, type="debit", client_id="payer_3",
            counterparty_address=CLEAN_EVM,
        )

        assert "sanctions_screening_unavailable" in codes(result)

    def test_reporting_an_unloaded_list_does_not_change_the_score(
        self, application, no_geoip,
    ):
        """It is a data-completeness marker, not evidence of wrongdoing."""
        result = transfer(
            application, type="debit", client_id="payer_4",
            counterparty_address=CLEAN_EVM,
        )

        assert result.risk_score == 0.0

    def test_a_stale_list_is_reported(self, application, no_geoip):
        from datetime import timedelta

        from django.utils import timezone
        from core.intelligence.sanctions import SanctionsList

        load()
        meta = SanctionsList.status()
        from django.core.cache import cache
        cache.set(SanctionsList.META_KEY, dict(
            meta, loaded_at=(timezone.now() - timedelta(days=30)).isoformat(),
        ))

        result = transfer(
            application, type="debit", client_id="payer_5",
            counterparty_address=CLEAN_EVM,
        )

        assert "sanctions_list_stale" in codes(result)

    def test_screening_is_a_control_not_technique_coverage(self):
        """
        A sanctions hit is a legal obligation, not a fraud technique. Counting
        it as F3 coverage would overstate what FLIT detects.
        """
        from core.audit.rules import SanctionedAddressRule
        from core.audit.rules.base_rule import RuleKind

        assert SanctionedAddressRule.kind == RuleKind.CONTROL
        assert SanctionedAddressRule.techniques == ()
