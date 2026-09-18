"""
Replay a merchant's historical payments through FLIT's rules.

    python manage.py backtest history.csv --mapping mapping.json --application "Fintech A"

Writes decisions, devices and labels into the database for the application
given, so use one created for the backtest rather than a live one.
"""

import json
from django.core.management.base import BaseCommand, CommandError

from core.models import Application, Organization, User
from core.backtest.loader import iter_rows, LoaderError
from core.backtest.mapping import EventMapping, MappingError
from core.backtest.replay import Replay, DEFAULT_LABEL_DELAY_DAYS
from core.backtest.report import build_report, format_report


class Command(BaseCommand):
    help = "Replay historical payments through the rules and report what FLIT would have caught"

    def add_arguments(self, parser):
        parser.add_argument("file", help="Export to replay (.csv, .json or .jsonl)")
        parser.add_argument("--mapping", required=True, help="Mapping file for the export's columns")
        parser.add_argument("--application", required=True, help="Name of the application to replay into")
        parser.add_argument("--create", action="store_true", help="Create the application if it is missing")
        parser.add_argument("--limit", type=int, help="Replay at most this many transactions")
        parser.add_argument("--label-delay-days", type=int, default=DEFAULT_LABEL_DELAY_DAYS,
                            help="How long after a transaction its outcome is reported (default 7)")
        parser.add_argument("--out", help="Write the full report as JSON to this path")

    def handle(self, *args, **options):
        try:
            mapping = EventMapping.load(options["mapping"])
            rows = iter_rows(options["file"])
        except (MappingError, LoaderError, OSError, ValueError) as error:
            raise CommandError(str(error))

        application = self.application(options["application"], create=options["create"])

        self.stdout.write(f"Replaying into {application.name} ({application.id})...")

        replay = Replay(
            application=application,
            mapping=mapping,
            label_delay_days=options["label_delay_days"],
            on_progress=self.progress,
        )

        try:
            results = replay.run(rows, limit=options["limit"])
        except (MappingError, LoaderError) as error:
            raise CommandError(str(error))

        report = build_report(
            results=results,
            skipped=replay.skipped,
            application=application,
            label_delay_days=options["label_delay_days"],
        )

        self.stdout.write("")
        self.stdout.write(format_report(report))

        if options["out"]:
            with open(options["out"], "w") as handle:
                json.dump(report, handle, indent=2, default=str)
            self.stdout.write(f"\nFull report: {options['out']}")

        if replay.skipped:
            self.stdout.write(self.style.WARNING(
                f"\n{len(replay.skipped)} rows skipped; first few: "
                + ", ".join(str(item["reason"]) for item in replay.skipped[:3])
            ))

    def progress(self, done, total):
        self.stdout.write(f"  {done}/{total}", ending="\r")

    def application(self, name, create=False):
        application = Application.objects.filter(name=name).first()

        if application:
            return application

        if not create:
            raise CommandError(f"No application named {name!r} (pass --create to make one)")

        owner, _ = User.objects.get_or_create(
            email="backtest@flit.io",
            defaults=dict(is_staff=False, is_active=False),
        )
        organization, _ = Organization.objects.get_or_create(name="Backtests", owner=owner)

        return Application.objects.create(name=name, organization=organization)
