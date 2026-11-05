from core.agent.cost import Usage, price_for, PRICES


class TestPricing:
    def test_known_models_resolve_including_dated_ids(self):
        assert price_for("claude-opus-5-5") == (PRICES["claude-opus-5-5"], True)
        assert price_for("claude-opus-5-5-20260301") == (PRICES["claude-opus-5-5"], True)
        assert price_for("claude-opus-5")[0] == PRICES["claude-opus-5"]

    def test_unknown_models_are_priced_and_flagged(self):
        prices, known = price_for("claude-future-9")
        assert known is False and prices == PRICES["claude-opus-5-5"]


class TestUsage:
    def test_cost_adds_every_token_class(self):
        usage = Usage()
        cost = usage.add(dict(input_tokens=1_000_000, output_tokens=100_000, cache_read_input_tokens=2_000_000, cache_creation_input_tokens=200_000), "claude-opus-5-5")
        # 4 + 2 + 0.4 + 1
        assert round(cost, 4) == 7.4
        assert usage.requests == 1
        assert usage.as_dict()["cost_usd"] == 7.4

    def test_missing_fields_are_zero(self):
        usage = Usage()
        usage.add(dict(input_tokens=500), "claude-opus-5-5")
        assert usage.counts["cache_read_input_tokens"] == 0

    def test_the_budget_line(self):
        usage = Usage(dict(cost_usd=0.1234))
        assert usage.budget_line(2.0) == "USD budget: $0.1234/$2.00; $1.88 remaining"
        usage.unknown_model = True
        assert "inaccurate" in usage.budget_line(2.0)
