"""
Tests for the crypto rails.

FLIT does not read chains — Chainalysis, TRM and Elliptic do that, and every
crypto fintech of any size already pays one. What those tools see poorly is
the half that happens before anything is signed: the device, the session, the
signup, the takeover. These tests cover FLIT's half.

Each behaviour is checked twice: that it fires on the fraud shape, and that
an ordinary customer doing something that looks similar does not trip it.
"""

import asyncio
from unittest.mock import AsyncMock, patch

from django.utils import timezone


EVM_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
OTHER_EVM = "0x1234567890AbcdEF1234567890aBcdef12345678"
TRON_ADDRESS = "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8"
COLLECTOR = "0xDEADBEEF00000000000000000000000000001234"


def transfer(application, *, client_id="user_1", type="debit", amount=100,
             chain="polygon", asset="USDC", wallet_address=None,
             counterparty_address=None, event_id=None):
    """One crypto movement, audited the way a merchant's API would send it."""
    from core.audit.auditor import Auditor
    from core.audit.events import TransactionEvent

    event = TransactionEvent(
        id=event_id or f"tx_{timezone.now().timestamp()}",
        type=type,
        amount=amount,
        currency_code="USD",
        client_id=client_id,
        chain=chain,
        asset=asset,
        wallet_address=wallet_address,
        counterparty_address=counterparty_address,
    )

    with patch(
        "core.services.fingerprint.FetchVisitData.async_call",
        AsyncMock(return_value=None),
    ):
        return asyncio.run(
            Auditor.audit(event, application.policy, send_alerts=False)
        )


def codes(result):
    return list(result.factors)


class TestWalletIntelligence:
    def test_checksummed_and_lowercase_evm_are_one_wallet(self):
        from core.intelligence.wallet_intelligence import address_key

        assert address_key(EVM_ADDRESS, "ethereum") == address_key(
            EVM_ADDRESS.lower(), "ethereum"
        )

    def test_the_same_evm_address_is_one_wallet_across_evm_chains(self):
        """
        A ring that collects on Polygon and withdraws on Base is one actor.
        Keying per chain would hide that.
        """
        from core.intelligence.wallet_intelligence import address_key

        assert address_key(EVM_ADDRESS, "polygon") == address_key(EVM_ADDRESS, "base")

    def test_case_sensitive_chains_are_left_alone(self):
        """Lowercasing a Tron or Solana address would break it."""
        from core.intelligence.wallet_intelligence import normalize_address

        assert normalize_address(TRON_ADDRESS, "tron") == TRON_ADDRESS

    def test_a_non_evm_address_on_an_evm_chain_is_refused(self):
        from core.intelligence.wallet_intelligence import address_key

        assert address_key(TRON_ADDRESS, "ethereum") is None

    def test_junk_is_refused_rather_than_keyed_on(self):
        from core.intelligence.wallet_intelligence import address_key

        for value in ("", None, "0x123", "not an address", "a" * 200):
            assert address_key(value, "ethereum") is None

    def test_redaction_is_readable_and_partial(self):
        from core.intelligence.wallet_intelligence import redact

        assert redact(EVM_ADDRESS) == "0x742d…f44e"


class TestWalletAsIdentity:
    def test_a_wallet_correlates_accounts_with_no_device_or_shared_ip(
        self, application, no_geoip,
    ):
        """
        The payoff of putting the wallet on the ladder: farming is detected
        with no device fingerprint, no shared IP and no shared email — only
        the wallet funding every account.
        """
        result = None

        for index in range(4):
            result = transfer(
                application,
                client_id=f"farmed_{index}",
                type="credit",
                wallet_address=EVM_ADDRESS,
            )

        assert "account_farming:wallet" in codes(result)

    def test_a_wallet_finding_outranks_an_ip_one(self):
        from core.scoring.weights import DEFAULT_WEIGHTS

        wallet = DEFAULT_WEIGHTS.get_weight("account_farming:wallet")
        ip = DEFAULT_WEIGHTS.get_weight("account_farming:ip")

        assert wallet > ip

    def test_two_accounts_from_one_wallet_is_not_a_farm(
        self, application, no_geoip,
    ):
        """People fund a second account for a partner. That is not a ring."""
        result = None

        for index in range(2):
            result = transfer(
                application,
                client_id=f"household_{index}",
                type="credit",
                wallet_address=EVM_ADDRESS,
            )

        assert "account_farming:wallet" not in codes(result)


class TestCryptoCashOut:
    def test_funds_arriving_and_leaving_on_chain_are_flagged(
        self, application, no_geoip,
    ):
        transfer(application, type="credit", amount=1000, client_id="mule_1")
        result = transfer(application, type="debit", amount=950, client_id="mule_1",
                          counterparty_address=COLLECTOR)

        assert "crypto_cash_out" in codes(result)

    def test_spending_part_of_a_balance_is_not_a_cash_out(
        self, application, no_geoip,
    ):
        transfer(application, type="credit", amount=1000, client_id="saver_1")
        result = transfer(application, type="debit", amount=50, client_id="saver_1",
                          counterparty_address=COLLECTOR)

        assert "crypto_cash_out" not in codes(result)

    def test_a_withdrawal_with_no_recent_funding_is_not_a_cash_out(
        self, application, no_geoip,
    ):
        result = transfer(application, type="debit", amount=500, client_id="holder_1",
                          counterparty_address=COLLECTOR)

        assert "crypto_cash_out" not in codes(result)


class TestNewWithdrawalAddress:
    def test_a_new_destination_after_an_established_pattern_is_flagged(
        self, application, no_geoip,
    ):
        for index in range(2):
            transfer(application, type="debit", client_id="regular_1",
                     counterparty_address=EVM_ADDRESS if index == 0 else OTHER_EVM)

        result = transfer(application, type="debit", client_id="regular_1",
                          counterparty_address=COLLECTOR)

        assert "new_withdrawal_address" in codes(result)

    def test_a_first_withdrawal_is_not_flagged(self, application, no_geoip):
        """
        Otherwise every new customer is taxed for doing the obvious thing.
        """
        result = transfer(application, type="debit", client_id="newcomer_1",
                          counterparty_address=EVM_ADDRESS)

        assert "new_withdrawal_address" not in codes(result)

    def test_returning_to_a_known_address_is_not_flagged(
        self, application, no_geoip,
    ):
        for address in (EVM_ADDRESS, OTHER_EVM):
            transfer(application, type="debit", client_id="regular_2",
                     counterparty_address=address)

        result = transfer(application, type="debit", client_id="regular_2",
                          counterparty_address=EVM_ADDRESS)

        assert "new_withdrawal_address" not in codes(result)


class TestCollectionWallet:
    def test_many_accounts_paying_one_address_is_flagged(
        self, application, no_geoip,
    ):
        result = None

        for index in range(6):
            result = transfer(application, type="debit", client_id=f"ring_{index}",
                              counterparty_address=COLLECTOR)

        assert "collection_wallet" in codes(result)

    def test_a_few_accounts_sharing_a_destination_is_not(
        self, application, no_geoip,
    ):
        """
        A couple, a family, or one person with two accounts legitimately send
        to the same place.
        """
        result = None

        for index in range(3):
            result = transfer(application, type="debit", client_id=f"family_{index}",
                              counterparty_address=EVM_ADDRESS)

        assert "collection_wallet" not in codes(result)

    def test_the_destination_is_never_treated_as_the_senders_identity(
        self, application, no_geoip,
    ):
        """
        If a shared destination were an identity key, every customer of one
        exchange would be merged into a single actor.
        """
        result = None

        for index in range(6):
            result = transfer(application, type="debit", client_id=f"payer_{index}",
                              counterparty_address=COLLECTOR)

        assert "account_farming:counterparty" not in codes(result)
        assert "multi_accounting:counterparty" not in codes(result)
        assert "counterparty" not in (result.identity["rungs"] or [])


class TestCashOutNeedsSomewhereToGo:
    """
    Regression from a real backtest. A platform that settles internally in
    stablecoin stamps a chain on nearly every row, so gating the cash-out
    rule on the chain alone made it fire on wallet-to-card movements that
    never left the platform.
    """

    def test_an_internal_movement_is_not_a_cash_out(
        self, application, no_geoip,
    ):
        transfer(application, type="credit", amount=1000, client_id="internal_1")
        result = transfer(
            application, type="debit", amount=950, client_id="internal_1",
            counterparty_address=None,
        )

        assert "crypto_cash_out" not in codes(result)

    def test_the_same_movement_to_an_external_address_is(
        self, application, no_geoip,
    ):
        transfer(application, type="credit", amount=1000, client_id="external_1")
        result = transfer(
            application, type="debit", amount=950, client_id="external_1",
            counterparty_address=COLLECTOR,
        )

        assert "crypto_cash_out" in codes(result)
