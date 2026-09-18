"""
Turns a replay into a calibration report.

The questions it answers: which rules fire, which of them actually separate
fraud from good customers, and what each block threshold would have cost in
blocked good customers.
"""

from core.scoring import DEFAULT_THRESHOLDS


FRAUD_LABELS = {"fraud", "chargeback"}
LEGIT_LABELS = {"legit", "false_positive"}

CURVE_STEPS = [round(0.05 * step, 2) for step in range(1, 20)]

# Reported for completeness, never scored, so they are noise in a lift table.
IGNORED_FACTORS = {"req_event_attrs"}


def build_report(*, results, skipped, application, label_delay_days):
    fraud = [row for row in results if row["label"] in FRAUD_LABELS]
    legit = [row for row in results if row["label"] in LEGIT_LABELS]

    return dict(
        application=application.name,
        replayed=len(results),
        skipped=len(skipped),
        skipped_examples=skipped[:10],
        label_delay_days=label_delay_days,
        window=window(results),
        labels=dict(
            fraud=len(fraud),
            legit=len(legit),
            unlabelled=len(results) - len(fraud) - len(legit),
        ),
        coverage=coverage(results),
        risk_levels=distribution(results, "risk_level"),
        current_policy=measure(results, fraud, legit, DEFAULT_THRESHOLDS.block_at),
        threshold_curve=[
            dict(block_at=threshold, **measure(results, fraud, legit, threshold))
            for threshold in CURVE_STEPS
        ],
        rules=rule_stats(results, fraud, legit),
    )


def window(results):
    if not results:
        return dict(start=None, end=None)

    timestamps = [row["timestamp"] for row in results]

    return dict(start=min(timestamps).isoformat(), end=max(timestamps).isoformat())


def coverage(results):
    """
    How much of the data FLIT could actually use. A rule cannot fire on a
    field the export never carried, and a report that hides that is
    misleading rather than merely incomplete.
    """
    total = len(results) or 1
    labelled = sum(1 for row in results if row["label"])

    return dict(
        labelled=round(labelled / total, 4),
        scored=round(sum(1 for row in results if row["risk_score"] > 0) / total, 4),
    )


def distribution(results, key):
    counts = {}

    for row in results:
        counts[row[key]] = counts.get(row[key], 0) + 1

    return counts


def measure(results, fraud, legit, block_at):
    blocked = [row for row in results if row["risk_score"] >= block_at]
    caught = sum(1 for row in blocked if row["label"] in FRAUD_LABELS)
    false_positives = sum(1 for row in blocked if row["label"] in LEGIT_LABELS)

    return dict(
        blocked=len(blocked),
        blocked_rate=ratio(len(blocked), len(results)),
        caught_fraud=caught,
        missed_fraud=len(fraud) - caught,
        false_positives=false_positives,
        # Of the good customers we know about, how many would be turned away.
        false_positive_rate=ratio(false_positives, len(legit)),
        precision=ratio(caught, caught + false_positives),
        recall=ratio(caught, len(fraud)),
    )


def rule_stats(results, fraud, legit):
    """
    Per factor: how often it fires, and how much more often on fraud than on
    good customers. Lift above 1 means the rule carries signal; at or below 1
    it is noise no matter how often it fires.
    """
    codes = {
        code
        for row in results
        for code in row["factors"]
        if code not in IGNORED_FACTORS
    }

    stats = []

    for code in sorted(codes):
        fired = [row for row in results if code in row["factors"]]
        on_fraud = sum(1 for row in fraud if code in row["factors"])
        on_legit = sum(1 for row in legit if code in row["factors"])

        fraud_rate = ratio(on_fraud, len(fraud))
        legit_rate = ratio(on_legit, len(legit))

        stats.append(dict(
            code=code,
            fired=len(fired),
            fired_rate=ratio(len(fired), len(results)),
            on_fraud=on_fraud,
            on_legit=on_legit,
            fraud_rate=fraud_rate,
            legit_rate=legit_rate,
            lift=round(fraud_rate / legit_rate, 2) if fraud_rate and legit_rate else None,
            # A rule that never fires on a good customer has no finite lift,
            # and is the most useful kind there is.
            only_on_fraud=bool(on_fraud and not on_legit),
            precision=ratio(on_fraud, on_fraud + on_legit),
        ))

    return sorted(
        stats,
        key=lambda item: (
            not item["only_on_fraud"],
            -(item["lift"] or 0),
            -item["on_fraud"],
        ),
    )


def ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


def format_report(report):
    """A readable summary; the JSON file holds everything."""
    lines = []
    add = lines.append

    add(f"Backtest: {report['application']}")
    add(f"  replayed {report['replayed']} transactions, skipped {report['skipped']}")
    add(f"  window   {report['window']['start']} -> {report['window']['end']}")

    labels = report["labels"]
    add(f"  labels   {labels['fraud']} fraud, {labels['legit']} legit, {labels['unlabelled']} unlabelled "
        f"(reported after {report['label_delay_days']} days)")

    if not labels["fraud"]:
        add("")
        add("  No fraud labels: rule firing rates are shown, but precision,")
        add("  recall and the threshold curve cannot be measured.")

    current = report["current_policy"]
    add("")
    add(f"Current policy (block at {DEFAULT_THRESHOLDS.block_at})")
    add(f"  blocked {current['blocked']} ({percent(current['blocked_rate'])}), "
        f"caught {current['caught_fraud']}, missed {current['missed_fraud']}, "
        f"false positives {current['false_positives']} ({percent(current['false_positive_rate'])})")
    add(f"  precision {current['precision']}, recall {current['recall']}")

    if labels["fraud"]:
        add("")
        add("Threshold curve")
        add(f"  {'block_at':>9} {'blocked':>8} {'caught':>7} {'missed':>7} {'false+':>7} {'prec':>6} {'recall':>7}")
        for point in report["threshold_curve"]:
            add(f"  {point['block_at']:>9} {point['blocked']:>8} {point['caught_fraud']:>7} "
                f"{point['missed_fraud']:>7} {point['false_positives']:>7} "
                f"{str(point['precision']):>6} {str(point['recall']):>7}")

    add("")
    add("Rules (by lift: how much more often a rule fires on fraud than on good customers)")
    add(f"  {'rule':<32} {'fired':>6} {'fraud':>6} {'legit':>6} {'lift':>10}")
    for rule in report["rules"][:25]:
        lift = "fraud only" if rule["only_on_fraud"] else str(rule["lift"])
        add(f"  {rule['code']:<32} {rule['fired']:>6} {rule['on_fraud']:>6} "
            f"{rule['on_legit']:>6} {lift:>10}")

    if not report["rules"]:
        add("  no rules fired")

    return "\n".join(lines)


def percent(value):
    return f"{value:.1%}" if value is not None else "n/a"
