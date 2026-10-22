"""
The evidence ledger: what a measured claim actually rests on.

A detector may sit anywhere on the maturity ladder, but from `backtested`
upward the claim is numerical, and a number with no dataset behind it is
worse than no number — it reads as fact and cannot be checked. The ledger is
where those numbers live: written by the backtest command, never by hand, and
keyed by the rule code the measurement was taken on.

A rule claiming a measured rung names the codes its claim rests on in
`evidence_codes`, and the test suite refuses the claim if the ledger has no
entry for them. Nothing currently claims one, which is the honest state of
the product; this is the gate for when something does.
"""

import json
from pathlib import Path

from django.conf import settings


LEDGER_NAME = "evidence.json"


def ledger_path():
    base = getattr(settings, "BASE_DIR", None) or Path.cwd()
    return Path(base).parent / LEDGER_NAME


def load(path=None):
    path = Path(path) if path else ledger_path()

    if not path.exists():
        return {}

    try:
        return json.loads(path.read_text()).get("codes", {})
    except (ValueError, OSError):
        return {}


def record(*, entries, application, window, path=None):
    """
    Write measurements for one backtest run.

    Entries are merged by code, most recent measurement winning, so a rule
    measured against several portfolios keeps the latest for each.
    """
    path = Path(path) if path else ledger_path()
    existing = load(path)

    for code, measurement in entries.items():
        existing[code] = dict(
            measurement, application=application, window=window,
        )

    path.write_text(json.dumps(
        dict(codes=existing), indent=2, sort_keys=True,
    ))

    return len(entries)


def from_backtest(report):
    """Turn a backtest report's per-rule statistics into ledger entries."""
    entries = {}

    for row in report.get("rules") or []:
        entries[row["code"]] = dict(
            precision=row.get("precision"),
            lift=row.get("lift"),
            fired=row.get("fired"),
            on_fraud=row.get("on_fraud"),
            on_legit=row.get("on_legit"),
            only_on_fraud=row.get("only_on_fraud"),
            measured_at=report.get("generated_at"),
        )

    return entries


def unsupported_claims(detector_rows, ledger=None):
    """
    Detectors claiming a measured rung whose evidence codes are not in the
    ledger. The test suite treats a non-empty result as a failure.
    """
    from .maturity import Maturity

    ledger = load() if ledger is None else ledger
    offenders = []

    for row in detector_rows:
        if not Maturity.is_measured(row["maturity"]):
            continue

        codes = row.get("evidence_codes") or []

        if not codes:
            offenders.append(f"{row['rule']} (names no evidence codes)")
            continue

        missing = [code for code in codes if code not in ledger]
        if missing:
            offenders.append(f"{row['rule']} ({', '.join(missing)} not measured)")

    return offenders
