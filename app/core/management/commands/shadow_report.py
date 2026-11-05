"""
What a rule running in shadow would have done.

A rule earns the shadow-validated rung by running against live traffic
without acting on anyone, and being measured. This is the measurement: for
each shadow finding in the window, how often it fired, on what the reviewers
later labelled, and how often it agreed with the live decision.

    python manage.py shadow_report --application "Figo" --days 14
    python manage.py shadow_report --application "Figo" --days 14 --record-evidence

With --record-evidence the per-code results are written to the evidence
ledger, which is what lets the rule claim the rung.
"""

import json
from collections import defaultdict
from decimal import Decimal
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.audit.models import AuditLogLabel
from core.models import Application, AuditLog
from core.taxonomy import evidence


from core.loss import Loss, to_amount, is_currency_code


def amount_of(row):
    """(amount, currency) of a report row: the reported loss, else the transaction's."""
    if row.get("loss_amount") is not None:
        return row["loss_amount"], row.get("loss_currency")
    context = row.get("context") or {}
    amount = to_amount(context.get("amount"))
    currency = context.get("currency_code")
    if amount is None or not is_currency_code(currency or ""):
        return None, None
    return amount, currency


FRAUD = {AuditLogLabel.FRAUD, AuditLogLabel.CHARGEBACK}
LEGIT = {AuditLogLabel.LEGIT, AuditLogLabel.FALSE_POSITIVE}


def ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None


class Command(BaseCommand):
    help = "Measure the rules running in shadow against recorded decisions and labels"

    def add_arguments(self, parser):
        parser.add_argument("--application", required=True, help="Application name")
        parser.add_argument("--days", type=int, default=14)
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--record-evidence", action="store_true",
                            help="Write the measured per-code results into the evidence ledger")

    def handle(self, *args, **options):
        application = Application.objects.filter(name=options["application"]).first()
        if not application:
            raise CommandError(f"No application named {options['application']!r}")

        since = timezone.now() - timedelta(days=options["days"])
        rows = list(
            AuditLog.objects
            .filter(application_id=application.id, timestamp__gte=since)
            .values("context", "label", "risk_score", "loss_amount", "loss_currency")
        )

        report = self.measure(rows, application, options["days"])

        if options["json"]:
            self.stdout.write(json.dumps(report, indent=2, default=str))
        else:
            self.stdout.write(self.render(report))

        if options["record_evidence"]:
            if not report["labels"]["fraud"]:
                self.stdout.write(self.style.WARNING(
                    "No fraud labels in this window: nothing recorded as evidence."
                ))
                return
            written = evidence.record(
                entries={code: dict(
                    precision=row["precision"], lift=row["lift"], fired=row["fired"],
                    on_fraud=row["on_fraud"], on_legit=row["on_legit"],
                    only_on_fraud=row["on_legit"] == 0 and row["on_fraud"] > 0,
                    agreement=row["agreement"], source="shadow",
                    measured_at=timezone.now().isoformat(),
                ) for code, row in report["codes"].items()},
                application=application.name,
                window=report["window"],
            )
            self.stdout.write(f"Recorded {written} code(s) in the evidence ledger.")

    @classmethod
    def measure(cls, rows, application, days):
        fraud = [row for row in rows if row["label"] in FRAUD]
        legit = [row for row in rows if row["label"] in LEGIT]

        per_code = defaultdict(lambda: dict(
            fired=0, on_fraud=0, on_legit=0, agreed=0, rule=None,
            fraud_amount=Decimal(0), legit_amount=Decimal(0),
        ))
        # Money in the application's own currency only; anything else is
        # counted but not summed, and said so.
        currency = Loss.currency_of(application.policy)
        unpriced = 0

        for row in rows:
            context = row["context"] or {}
            live_blocked = bool(context.get("should_block"))
            amount, row_currency = amount_of(row)
            priced = amount is not None and row_currency == currency
            if row["label"] in FRAUD | LEGIT and not priced:
                unpriced += 1
            seen = set()
            for finding in context.get("shadow") or []:
                code = finding.get("code")
                if not code or code in seen:
                    continue
                seen.add(code)
                stats = per_code[code]
                stats["rule"] = finding.get("rule")
                stats["fired"] += 1
                stats["on_fraud"] += row["label"] in FRAUD
                stats["on_legit"] += row["label"] in LEGIT
                stats["agreed"] += live_blocked
                if priced and row["label"] in FRAUD:
                    stats["fraud_amount"] += amount
                if priced and row["label"] in LEGIT:
                    stats["legit_amount"] += amount

        codes = {}
        for code, stats in sorted(per_code.items()):
            fraud_rate = ratio(stats["on_fraud"], len(fraud))
            legit_rate = ratio(stats["on_legit"], len(legit))
            codes[code] = dict(
                rule=stats["rule"],
                fired=stats["fired"],
                on_fraud=stats["on_fraud"],
                on_legit=stats["on_legit"],
                precision=ratio(stats["on_fraud"], stats["on_fraud"] + stats["on_legit"]),
                lift=round(fraud_rate / legit_rate, 2) if fraud_rate and legit_rate else None,
                # How often the live decision blocked when the shadow rule fired.
                agreement=ratio(stats["agreed"], stats["fired"]),
                # The money behind the counts: fraud this code would have
                # caught, and good customers' money it would have turned away.
                fraud_amount=float(stats["fraud_amount"]),
                legit_amount=float(stats["legit_amount"]),
            )

        return dict(
            application=application.name,
            window=dict(days=days, decisions=len(rows)),
            labels=dict(fraud=len(fraud), legit=len(legit), unlabelled=len(rows) - len(fraud) - len(legit)),
            money=dict(currency=currency, unpriced=unpriced),
            codes=codes,
        )

    @staticmethod
    def render(report):
        lines = [
            f"Shadow report for {report['application']}: {report['window']['decisions']} decisions "
            f"in {report['window']['days']} days; labels fraud={report['labels']['fraud']} "
            f"legit={report['labels']['legit']}",
            "",
            f"  money in {report['money']['currency'] or 'no currency'}; {report['money']['unpriced']} labelled rows unpriced",
            f"  {'code':<34} {'rule':<26} {'fired':>6} {'fraud':>6} {'legit':>6} {'prec':>6} {'lift':>6} {'agree':>6} "
            f"{'fraud money':>14} {'legit money':>14}",
        ]
        for code, row in report["codes"].items():
            lines.append(
                f"  {code:<34} {str(row['rule']):<26} {row['fired']:>6} {row['on_fraud']:>6} "
                f"{row['on_legit']:>6} {str(row['precision']):>6} {str(row['lift']):>6} {str(row['agreement']):>6} "
                f"{row['fraud_amount']:>14,.2f} {row['legit_amount']:>14,.2f}"
            )
        if not report["codes"]:
            lines.append("  (no shadow findings in the window)")
        return "\n".join(lines)
