"""
Money, as the unit a decision is judged by.

A label says what happened. It does not say what it cost, and a system that
counts labels treats a five-dollar false positive and a fifty-thousand-dollar
mule transfer as one row each. FLIT exists to prevent money loss, so the
amount has to travel with the outcome: every labelled decision carries the
money at stake, the loss ledger adds it up, and the calibrator refuses a
weight change that would lose more of it.

Two sources, in order. The merchant may report an amount with the label —
the loss as they measured it, after any recovery. Otherwise the decision's
own transaction amount stands in; for a payment that is usually the right
number anyway. A decision with no amount from either source is "unpriced":
counted, never summed, and reported as such so a ledger is never quietly
short.

Sums are kept per currency. Converting across currencies needs a rate and a
date, and a ledger that silently picks one is a ledger that cannot be
audited. The calibrator sums only the application's own currency, the one
its AML limit is written in, and reports how many rows it could not price.
"""

from collections import defaultdict
from datetime import timedelta
from decimal import Decimal, InvalidOperation

from django.utils import timezone

from core.money import init_money, MoneyFormatError


FRAUD_LABELS = {"fraud", "chargeback"}
LEGIT_LABELS = {"legit", "false_positive"}


def to_amount(value):
    """A non-negative Decimal with two places, or None."""
    if value is None or isinstance(value, bool):
        return None
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    if not amount.is_finite() or amount < 0:
        return None
    return amount.quantize(Decimal("0.01"))


def is_currency_code(value):
    return isinstance(value, str) and len(value) == 3 and value.isalpha() and value.isupper()


class Loss:

    @staticmethod
    def currency_of(policy):
        """The currency an application's money is reckoned in."""
        try:
            return init_money(policy.aml_cft_limit).currency.code
        except (MoneyFormatError, AttributeError, TypeError):
            return None

    @staticmethod
    def at_stake(decision):
        """
        (amount, currency) for a decision, or (None, None) if unpriced.

        A reported loss wins; the transaction's own amount is the fallback.
        """
        if decision.loss_amount is not None:
            return decision.loss_amount, decision.loss_currency

        context = decision.context or {}
        amount = to_amount(context.get("amount"))
        currency = context.get("currency_code")
        if amount is None or not is_currency_code(currency or ""):
            return None, None
        return amount, currency

    @staticmethod
    def is_fraud(decision):
        return decision.label in FRAUD_LABELS

    @staticmethod
    def is_legit(decision):
        return decision.label in LEGIT_LABELS


class LossReport:
    """
    What FLIT's decisions did to the merchant's money over a window.

    Per currency:

        prevented   fraud FLIT blocked while enforcing — money kept
        in_shadow   fraud FLIT would have blocked, but was not yet acting on
        flagged     fraud sent to review or challenge rather than blocked
        leaked      fraud FLIT allowed — money lost
        friction    legitimate customers FLIT blocked — business turned away
        net         prevented minus friction

    `unpriced` is how many labelled decisions carried no amount, so the sums
    are read as a floor, not a total.
    """

    DEFAULT_DAYS = 30
    MAX_DECISIONS = 50000

    @classmethod
    def call(cls, *, application, days=None):
        from core.audit.models import AuditLog

        days = days or cls.DEFAULT_DAYS
        since = timezone.now() - timedelta(days=days)
        decisions = (
            AuditLog.objects
            .filter(application_id=application.id, timestamp__gte=since, label__isnull=False)
            .order_by("-timestamp")[:cls.MAX_DECISIONS]
        )
        return cls.measure(list(decisions), application=application, days=days)

    @classmethod
    def measure(cls, decisions, *, application, days):
        by_currency = defaultdict(lambda: dict(
            prevented=Decimal(0), in_shadow=Decimal(0), flagged=Decimal(0),
            leaked=Decimal(0), friction=Decimal(0),
        ))
        counts = dict(fraud=0, legit=0, prevented=0, in_shadow=0, flagged=0, leaked=0, friction=0, unpriced=0)

        for decision in decisions:
            fraud = Loss.is_fraud(decision)
            legit = Loss.is_legit(decision)
            if not (fraud or legit):
                continue
            counts["fraud" if fraud else "legit"] += 1

            context = decision.context or {}
            blocked = bool(context.get("should_block"))
            flagged = bool(context.get("should_review") or context.get("should_challenge"))
            enforcing = context.get("enforcement") == "enforcing"

            if fraud:
                bucket = (
                    ("prevented" if enforcing else "in_shadow") if blocked
                    else "flagged" if flagged
                    else "leaked"
                )
            else:
                if not blocked:
                    continue
                bucket = "friction"
            counts[bucket] += 1

            amount, currency = Loss.at_stake(decision)
            if amount is None:
                counts["unpriced"] += 1
                continue
            by_currency[currency][bucket] += amount

        money = {}
        for currency, sums in sorted(by_currency.items()):
            kept = sums["prevented"]
            row = {key: cls.number(value) for key, value in sums.items()}
            row["net"] = cls.number(kept - sums["friction"])
            exposed = sums["prevented"] + sums["in_shadow"] + sums["flagged"] + sums["leaked"]
            row["leak_rate"] = cls.ratio(sums["leaked"], exposed)
            money[currency] = row

        return dict(
            application=application.name,
            enforcement=getattr(application, "enforcement", None),
            window=dict(days=days, labelled=counts["fraud"] + counts["legit"]),
            counts=counts,
            money=money,
            currency=Loss.currency_of(application.policy) if hasattr(application, "policy") else None,
        )

    @staticmethod
    def number(value):
        return float(value.quantize(Decimal("0.01")))

    @staticmethod
    def ratio(numerator, denominator):
        return round(float(numerator / denominator), 4) if denominator else None

    @staticmethod
    def render(report):
        counts = report["counts"]
        lines = [
            f"{report['application']} ({report['enforcement']}): {counts['fraud'] + counts['legit']} labelled "
            f"decisions in {report['window']['days']} days — {counts['fraud']} fraud, {counts['legit']} legit, "
            f"{counts['unpriced']} without an amount",
        ]
        if not report["money"]:
            lines.append("  nothing to add up: no labelled decision carried an amount")
            return "\n".join(lines)

        for currency, row in report["money"].items():
            lines.append(f"  {currency}")
            for key in ("prevented", "in_shadow", "flagged", "leaked", "friction"):
                lines.append(f"    {key:<11} {row[key]:>18,.2f}   ({counts[key]} decisions)")
            lines.append(f"    {'net':<11} {row['net']:>18,.2f}   prevented minus friction")
            leak = row["leak_rate"]
            lines.append(f"    {'leak rate':<11} {'—' if leak is None else f'{leak:.1%}':>18}   leaked / all fraud money")
        return "\n".join(lines)
