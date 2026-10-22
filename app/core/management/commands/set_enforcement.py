"""
Move an application between shadow and enforcing.

    python manage.py set_enforcement Figo enforcing

Turning enforcement on is the moment FLIT starts affecting real customers, so
it is a deliberate command rather than a checkbox, and it prints what the
application has actually seen so the decision is made against evidence.
"""

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.models import Application, AuditLog, Enforcement


class Command(BaseCommand):
    help = "Set an application's enforcement mode"

    def add_arguments(self, parser):
        parser.add_argument("name", help="Application name")
        parser.add_argument("mode", choices=Enforcement.VALUES)
        parser.add_argument(
            "--days", type=int, default=30,
            help="How far back to summarise decisions (default 30)",
        )

    def handle(self, *args, **options):
        application = Application.objects.filter(name=options["name"]).first()

        if not application:
            raise CommandError(f"No application named {options['name']!r}")

        since = timezone.now() - timedelta(days=options["days"])
        decisions = AuditLog.objects.filter(
            application_id=application.id, timestamp__gte=since,
        )

        total = decisions.count()
        would_block = sum(
            1 for row in decisions.values_list("context", flat=True)
            if (row or {}).get("should_block")
        )

        previous = application.enforcement
        application.enforcement = options["mode"]
        application.save(update_fields=["enforcement"])

        self.stdout.write(
            self.style.SUCCESS(
                f"{application.name}: {previous} -> {application.enforcement}"
            )
        )
        self.stdout.write("")
        self.stdout.write(f"  decisions in the last {options['days']} days  {total}")

        if total:
            share = would_block / total
            self.stdout.write(
                f"  of those, would block                {would_block} "
                f"({share:.1%})"
            )

        if options["mode"] == Enforcement.ENFORCING:
            if not total:
                self.stdout.write("")
                self.stdout.write(self.style.WARNING(
                    "This application has no recorded decisions. Enforcing "
                    "without a shadow period means the first thing FLIT does "
                    "to this merchant's customers is untested."
                ))
            self.stdout.write("")
            self.stdout.write(
                "Decisions now affect real customers. Watch the case queue."
            )
