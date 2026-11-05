"""
What FLIT's decisions did to a merchant's money.

    python manage.py loss_report --application "Figo"
    python manage.py loss_report --application "Figo" --days 90 --json

Adds up the outcomes the merchant reported, per currency: fraud blocked
(prevented, or in_shadow while FLIT was not yet acting), fraud sent to review
or challenge (flagged), fraud allowed (leaked), and good customers blocked
(friction). Rows without an amount are counted as unpriced, so the sums are
a floor. The same report is `GET /applications/{id}/loss`.
"""

import json

from django.core.management.base import BaseCommand, CommandError

from core.models import Application
from core.loss import LossReport


class Command(BaseCommand):
    help = "Add up what FLIT's decisions did to a merchant's money, from reported outcomes"

    def add_arguments(self, parser):
        parser.add_argument("--application", required=True, help="Application name")
        parser.add_argument("--days", type=int, default=LossReport.DEFAULT_DAYS)
        parser.add_argument("--json", action="store_true", help="Print the report as JSON")

    def handle(self, *args, **options):
        application = Application.objects.filter(name=options["application"]).first()
        if not application:
            raise CommandError(f"No application named {options['application']!r}")

        report = LossReport.call(application=application, days=options["days"])
        if options["json"]:
            self.stdout.write(json.dumps(report, indent=2))
        else:
            self.stdout.write(LossReport.render(report))
