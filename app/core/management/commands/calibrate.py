"""
Run the calibrator: learn from the last month of outcomes.

    python manage.py calibrate --all                 # nightly: dry run, prints what it would do
    python manage.py calibrate --all --apply         # nightly: applies what passes the guardrails
    python manage.py calibrate --application Figo    # one merchant

This is the always-on loop. Schedule the `--apply` form; the guardrails are
what make that safe, and every run is written to a CalibrationRun whether or
not it changed anything, so `GET /applications/{id}/calibrations` is the
review queue. A reviewer reads what moved and why, not the cases.
"""

from django.core.management.base import BaseCommand, CommandError

from core.models import Application
from core.calibration import Calibrator, format_run


class Command(BaseCommand):
    help = "Recalibrate an application's weights from its labelled outcomes"

    def add_arguments(self, parser):
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--application", help="Application name")
        target.add_argument("--all", action="store_true", help="Every application")
        parser.add_argument(
            "--days", type=int, default=Calibrator.WINDOW_DAYS,
            help=f"How much labelled history to learn from (default {Calibrator.WINDOW_DAYS})",
        )
        parser.add_argument(
            "--apply", action="store_true",
            help="Write accepted proposals to the policy. Without it, a dry run.",
        )

    def handle(self, *args, **options):
        if options["all"]:
            applications = list(Application.objects.order_by("name"))
        else:
            application = Application.objects.filter(name=options["application"]).first()
            if not application:
                raise CommandError(f"No application named {options['application']!r}")
            applications = [application]

        for application in applications:
            run = Calibrator.run(
                application=application, days=options["days"], apply=options["apply"],
            )
            self.stdout.write(format_run(run))
            self.stdout.write("")
