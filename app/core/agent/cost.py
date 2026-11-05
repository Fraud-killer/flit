"""
What a run costs, in dollars, as it goes.

Per request: input, output, cache-read and cache-write tokens at the model's
prices. The investigation carries its running total; a run that reaches its
budget ends with a report of what it found so far, and the model sees its
budget line every turn so it can spend the rest well. Unknown models are
priced at the default tier and flagged, so a wrong price is visible rather
than silently zero.
"""

# USD per million tokens: input, output, cache read, cache write.
PRICES = {
    "claude-opus-5-5":   (4.00, 20.00, 0.20, 5.00),
    "claude-opus-5":     (5.00, 25.00, 0.50, 6.25),
    "claude-sonnet-5-5": (3.00, 15.00, 0.30, 3.75),
    "claude-sonnet-5":   (3.00, 15.00, 0.30, 3.75),
    "claude-haiku-5-5":  (1.00,  5.00, 0.10, 1.25),
}
DEFAULT_PRICE = PRICES["claude-opus-5-5"]


def price_for(model):
    """(prices, known). A dated id like `claude-opus-5-5-20260101` resolves to its family."""
    if not model:
        return DEFAULT_PRICE, False
    for name, prices in sorted(PRICES.items(), key=lambda item: -len(item[0])):
        if model == name or model.startswith(name + "-"):
            return prices, True
    return DEFAULT_PRICE, False


class Usage:
    FIELDS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")

    def __init__(self, data=None):
        data = data or {}
        self.counts = {field: int(data.get(field) or 0) for field in self.FIELDS}
        self.requests = int(data.get("requests") or 0)
        self.cost_usd = float(data.get("cost_usd") or 0.0)
        self.unknown_model = bool(data.get("unknown_model", False))

    @staticmethod
    def read(response_usage):
        """Token counts from an SDK usage object or a dict; missing fields are zero."""
        counts = {}
        for field in Usage.FIELDS:
            value = (
                response_usage.get(field) if isinstance(response_usage, dict)
                else getattr(response_usage, field, None)
            ) if response_usage is not None else None
            counts[field] = int(value or 0)
        return counts

    def add(self, response_usage, model):
        counts = self.read(response_usage)
        prices, known = price_for(model)
        cost = (
            counts["input_tokens"] * prices[0]
            + counts["output_tokens"] * prices[1]
            + counts["cache_read_input_tokens"] * prices[2]
            + counts["cache_creation_input_tokens"] * prices[3]
        ) / 1_000_000
        for field in self.FIELDS:
            self.counts[field] += counts[field]
        self.requests += 1
        self.cost_usd += cost
        self.unknown_model = self.unknown_model or not known
        return cost

    def as_dict(self):
        return dict(self.counts, requests=self.requests, cost_usd=round(self.cost_usd, 6), unknown_model=self.unknown_model)

    @staticmethod
    def format_usd(amount):
        return f"${amount:.2f}" if amount >= 0.5 else f"${amount:.4f}"

    def budget_line(self, limit):
        remaining = max(0.0, limit - self.cost_usd)
        line = f"USD budget: {self.format_usd(self.cost_usd)}/{self.format_usd(limit)}; {self.format_usd(remaining)} remaining"
        if self.unknown_model:
            line += " (costs may be inaccurate: unknown model price)"
        return line
