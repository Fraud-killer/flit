"""
Refresh the Tor exit node list and IP threat blocklist used by IPIntelligence.

The lists are stored in the shared Django cache (Redis in production), so run
this on a schedule (e.g. hourly via cron) from any one host:

    python manage.py refresh_threat_intel
"""

from django.core.management.base import BaseCommand, CommandError
from core.intelligence.ip_intelligence import IPIntelligence


class Command(BaseCommand):
    help = "Download the Tor exit node list and IP threat blocklist into the cache"

    def add_arguments(self, parser):
        parser.add_argument(
            "--threat-list-url",
            help="Override THREAT_LIST_URL for this run",
        )

    def handle(self, *args, **options):
        failures = []

        try:
            count = IPIntelligence.refresh_tor_exit_nodes()
            self.stdout.write(f"Tor exit nodes: {count}")
        except Exception as error:
            failures.append(f"Tor exit nodes: {error}")

        try:
            count = IPIntelligence.refresh_threat_list(options["threat_list_url"])
            self.stdout.write(f"Threat list entries: {count}")
        except Exception as error:
            failures.append(f"Threat list: {error}")

        if failures:
            raise CommandError("; ".join(failures))

        self.stdout.write(self.style.SUCCESS("Threat intelligence refreshed"))
