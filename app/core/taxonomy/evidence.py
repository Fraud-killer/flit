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


# Where a dataset's labels came from decides what a measurement can prove.
# `incident_record` means the labels were derived from features of the attack
# itself (hostile addresses, scripted client strings, throwaway domains, the
# window the attacker held an account). A rule that reads those same features
# measured against those labels is measuring the labeller, not the fraud: the
# entry is kept, marked circular, and does not support a measured rung.
LABEL_SOURCES = ("merchant_outcomes", "reviewer_labels", "incident_record", "unknown")

# Features an incident record labels on, and the rule codes that read them.
CIRCULAR_CODES = {
    "incident_record": {
        "disposable_email_domain", "reserved_email_domain", "bot_detected:http_client",
        "bot_detected:automation", "suspicious_user_agent", "implausible_client_ip",
        "account_farming:ip", "multi_accounting:ip", "account_farming:asn", "multi_accounting:asn",
        "machine_session", "agent_session", "block_streak", "threat_ip", "tor_exit_node",
        "datacenter_ip", "ip_blocklisted",
    },
}


def is_circular(code, label_source):
    return code in CIRCULAR_CODES.get(label_source or "", set())


def record(*, entries, application, window, path=None, label_source=None):
    """
    Write measurements for one backtest run.

    Entries are merged by code, most recent measurement winning, so a rule
    measured against several portfolios keeps the latest for each. Every
    entry records where its labels came from and whether the measurement is
    circular for that code.
    """
    path = Path(path) if path else ledger_path()
    existing = load(path)
    label_source = label_source if label_source in LABEL_SOURCES else "unknown"

    for code, measurement in entries.items():
        existing[code] = dict(
            measurement, application=application, window=window,
            label_source=label_source, circular=is_circular(code, label_source),
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
            continue

        # A measurement whose labels were derived from the features the rule
        # reads proves nothing about the rule. It stays in the ledger as a
        # record of the replay, and it does not carry a rung.
        circular = [code for code in codes if ledger[code].get("circular")]
        if circular:
            offenders.append(f"{row['rule']} ({', '.join(circular)} measured against circular labels)")

    return offenders


def notes(ledger=None):
    """One line per code whose measurement needs a caveat, for the matrix."""
    ledger = load() if ledger is None else ledger
    lines = []
    for code, entry in sorted(ledger.items()):
        if entry.get("circular"):
            lines.append(
                f"`{code}`: measured on {entry.get('application')} with labels from "
                f"{entry.get('label_source', 'unknown').replace('_', ' ')}; the rule reads the same "
                "features the labels were derived from, so this is an incident replay, not evidence."
            )
    return lines
