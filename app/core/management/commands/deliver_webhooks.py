"""
Drain the webhook queue. Run every minute.

    python manage.py deliver_webhooks --limit 200
"""

from django.core.management.base import BaseCommand

from core.outbound.webhooks import Webhooks


class Command(BaseCommand):
    help = "Deliver queued webhooks to merchants, with backoff"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=200)

    def handle(self, *args, **options):
        from core.services.job_lock import JobLock, JobLocked

        try:
            with JobLock.hold("deliver_webhooks"):
                return self.run(*args, **options)
        except JobLocked as held:
            self.stdout.write(self.style.WARNING(f"Skipped: {held}"))
            return

    def run(self, *args, **options):
        delivered, failed = Webhooks.drain(limit=options["limit"])
        self.stdout.write(f"delivered {delivered}, failed {failed}")
