"""
Close out step-up challenges nobody came back to.

    python manage.py expire_challenges

Run it on a schedule, every few minutes. Abandonment is the most common
outcome of a challenge that worked — the script simply moves on — and it is
only a signal if something records it. Without this running, a challenge
teaches FLIT nothing unless the actor bothers to fail it.
"""

from django.core.management.base import BaseCommand, CommandError

from core.models import Application
from core.services.challenges import ExpireChallenges


class Command(BaseCommand):
    help = "Expire abandoned challenges and record the abandonment"

    def add_arguments(self, parser):
        parser.add_argument(
            "--application",
            help="Limit to one application by name (default: all)",
        )
        parser.add_argument(
            "--limit", type=int, default=500,
            help="Expire at most this many in one run (default 500)",
        )

    def handle(self, *args, **options):
        application = None
        name = options.get("application")

        if name:
            application = Application.objects.filter(name=name).first()
            if not application:
                raise CommandError(f"No application named {name!r}")

        expired = ExpireChallenges.call(
            application=application, limit=options["limit"],
        )

        self.stdout.write(
            self.style.SUCCESS(f"Expired {expired} abandoned challenges")
        )
