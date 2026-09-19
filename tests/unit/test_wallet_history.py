"""
Tests for on-chain wallet history.

FLIT asks a public node exactly one question — has this address ever sent a
transaction — and draws exactly one conclusion from it. These tests care as
much about what happens when the node does not answer as about when it does,
because an unreachable node must never read as clean.

Nothing here touches a real chain: lookups are disabled suite-wide in
conftest and re-enabled against stubs.
"""

import asyncio
from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

import pytest

from tests.unit.test_crypto import EVM_ADDRESS, TRON_ADDRESS, codes, transfer


@pytest.fixture(autouse=True)
def clear_wallet_cache():
    """
    A wallet's history is cached for thirty days, which is right in
    production and wrong between tests: the second lookup of an address would
    answer from the first test's stub. The conftest `mock_cache` fixture does
    not help here — it patches `django.core.cache.cache`, which has no effect
    on a module that imported `cache` directly.
    """
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


@contextmanager
def chain(*, nonce=None, code="0x", rpc_error=None):
    """Turn lookups on with a stubbed node. `nonce=None` means unknown."""
    from core.intelligence.wallet_intelligence import WalletChainIntelligence

    async def rpc(url, method, params):
        if rpc_error:
            raise rpc_error
        if method == "eth_getTransactionCount":
            return None if nonce is None else hex(nonce)
        if method == "eth_getCode":
            return code
        return None

    with patch.object(
        WalletChainIntelligence, "enabled", classmethod(lambda cls: True),
    ), patch(
        "core.intelligence.wallet_intelligence._rpc", AsyncMock(side_effect=rpc),
    ):
        yield


def analyze(address, chain_name="polygon", **kwargs):
    from core.intelligence.wallet_intelligence import WalletChainIntelligence

    with chain(**kwargs):
        return asyncio.run(WalletChainIntelligence.analyze(address, chain_name))


class TestWalletHistory:
    def test_a_wallet_that_has_never_sent_anything_is_fresh(self):
        history = analyze(EVM_ADDRESS, nonce=0)

        assert history.transaction_count == 0
        assert history.is_fresh
        assert not history.has_history

    def test_a_wallet_with_history_is_not(self):
        history = analyze(EVM_ADDRESS, nonce=412)

        assert history.transaction_count == 412
        assert history.has_history
        assert not history.is_fresh

    def test_an_unreachable_node_reads_as_unknown(self):
        """
        The important one. A node that does not answer must not read as
        clean, and must not read as suspicious either.
        """
        history = analyze(EVM_ADDRESS, rpc_error=OSError("node down"))

        assert history.transaction_count is None
        assert not history.is_fresh
        assert not history.has_history

    def test_a_contract_address_is_identified(self):
        history = analyze(EVM_ADDRESS, nonce=1, code="0x60806040")

        assert history.is_contract is True

    def test_a_non_evm_address_is_not_guessed_at(self):
        """Only EVM is supported; everything else returns unknown."""
        history = analyze(TRON_ADDRESS, chain_name="tron", nonce=0)

        assert history.checked is False
        assert history.transaction_count is None

    def test_an_unknown_chain_has_no_endpoint(self):
        history = analyze(EVM_ADDRESS, chain_name="hyperledger", nonce=0)

        assert history.transaction_count is None

    def test_lookups_stay_off_when_disabled(self):
        from core.intelligence.wallet_intelligence import WalletChainIntelligence

        with patch(
            "core.intelligence.wallet_intelligence._rpc", AsyncMock(return_value="0x0"),
        ) as rpc:
            history = asyncio.run(
                WalletChainIntelligence.analyze(EVM_ADDRESS, "polygon")
            )

        assert history.checked is False
        rpc.assert_not_called()


class TestFreshFundingWalletRule:
    def test_funding_from_a_brand_new_wallet_is_flagged(
        self, application, no_geoip,
    ):
        with chain(nonce=0):
            result = transfer(
                application, type="credit", client_id="farmed_1",
                counterparty_address=EVM_ADDRESS,
            )

        assert "fresh_funding_wallet" in codes(result)

    def test_funding_from_an_established_wallet_is_not(
        self, application, no_geoip,
    ):
        with chain(nonce=412):
            result = transfer(
                application, type="credit", client_id="regular_1",
                counterparty_address=EVM_ADDRESS,
            )

        assert "fresh_funding_wallet" not in codes(result)

    def test_an_unreachable_node_produces_no_finding(
        self, application, no_geoip,
    ):
        with chain(rpc_error=OSError("node down")):
            result = transfer(
                application, type="credit", client_id="unknown_1",
                counterparty_address=EVM_ADDRESS,
            )

        assert "fresh_funding_wallet" not in codes(result)

    def test_a_withdrawal_to_a_fresh_address_is_not_flagged(
        self, application, no_geoip,
    ):
        """
        Generating a fresh address to receive into is ordinary. The rule is
        about where money came from, not where it went.
        """
        with chain(nonce=0):
            result = transfer(
                application, type="debit", client_id="sender_1",
                counterparty_address=EVM_ADDRESS,
            )

        assert "fresh_funding_wallet" not in codes(result)

    def test_it_corroborates_rather_than_decides(self):
        """
        Somebody's genuine first transaction is somebody's first transaction.
        This must not block an account on its own.
        """
        from core.scoring import RiskEngine

        result = RiskEngine().calculate_risk(
            [{"code": "fresh_funding_wallet", "text": "", "context": {"severity": 0.5}}],
            event_category="transaction",
        )

        assert not result.should_block
        assert not result.should_challenge
