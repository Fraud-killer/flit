"""
Compare two backtested portfolios.

    python manage.py backtest_overlap "Fintech A" "Fintech B"

Answers the consortium question: how much of one portfolio's fraud was
already visible in the other.
"""

import json
from django.core.management.base import BaseCommand, CommandError

from core.models import Application
from core.backtest.overlap import compare, format_overlap


class Command(BaseCommand):
    help = "Measure device, counterparty and IP overlap between two applications"

    def add_arguments(self, parser):
        parser.add_argument("first", help="Name of the first application")
        parser.add_argument("second", help="Name of the second application")
        parser.add_argument("--out", help="Write the full result as JSON to this path")

    def handle(self, *args, **options):
        first = self.application(options["first"])
        second = self.application(options["second"])

        result = compare(first, second)

        self.stdout.write(format_overlap(result))

        if options["out"]:
            with open(options["out"], "w") as handle:
                json.dump(result, handle, indent=2, default=str)
            self.stdout.write(f"\nFull result: {options['out']}")

    def application(self, name):
        application = Application.objects.filter(name=name).first()

        if not application:
            raise CommandError(f"No application named {name!r}")

        return application
