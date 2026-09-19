"""
Refresh the OFAC sanctions list used for wallet screening.

    python manage.py refresh_sanctions

Schedule it daily and alert on failure. OFAC updates the SDN list several
times a month, and a list that quietly stopped refreshing is worse than no
list at all: screening still appears to happen, and it no longer does.

A run that finds no addresses fails rather than overwriting what is loaded,
so a changed format or a truncated download cannot empty the list.
"""

from django.core.management.base import BaseCommand, CommandError

from core.intelligence.sanctions import SanctionsList


class Command(BaseCommand):
    help = "Download the OFAC SDN digital currency addresses into the cache"

    def add_arguments(self, parser):
        parser.add_argument(
            "--url", help="Override SANCTIONS_LIST_URL for this run",
        )

    def handle(self, *args, **options):
        try:
            count = SanctionsList.refresh(options["url"])
        except Exception as error:
            raise CommandError(f"Could not refresh the sanctions list: {error}")

        status = SanctionsList.status()
        self.stdout.write(
            self.style.SUCCESS(f"Loaded {count} sanctioned addresses")
        )
        self.stdout.write(f"  source {status['source']}")
