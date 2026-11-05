"""
The agent worker: drains queued investigations.

    python manage.py run_investigations --limit 5          # one pass (cron)
    python manage.py run_investigations --loop --interval 5 # a long-running worker

Picks the oldest queued runs first, including runs a person just answered.
One worker at a time per deployment, under the job lock; a run that hangs is
reclaimed when the lock goes stale.
"""

import time

from django.core.management.base import BaseCommand

from core.models import Investigation, InvestigationStatus


class Command(BaseCommand):
    help = "Run queued Agent FLIT investigations"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=5)
        parser.add_argument("--loop", action="store_true")
        parser.add_argument("--interval", type=float, default=5.0, help="Seconds between passes in --loop")

    def handle(self, *args, **options):
        from core.services.job_lock import JobLock, JobLocked

        try:
            with JobLock.hold("run_investigations", stale_seconds=30 * 60):
                if options["loop"]:
                    while True:
                        ran = self.run_pass(options["limit"])
                        if not ran:
                            time.sleep(options["interval"])
                else:
                    self.run_pass(options["limit"])
        except JobLocked as held:
            self.stdout.write(self.style.WARNING(f"Skipped: {held}"))

    def run_pass(self, limit):
        from core.agent import InvestigationRunner, AgentGuardrails

        if not AgentGuardrails.enabled_globally():
            return 0
        queued = list(
            Investigation.objects.filter(status=InvestigationStatus.QUEUED)
            .select_related("application__organization").order_by("created_at")[:limit]
        )
        for investigation in queued:
            investigation = InvestigationRunner.start(investigation)
            self.stdout.write(f"{investigation.id} {investigation.playbook} → {investigation.status} (${investigation.cost_usd:.4f})")
        return len(queued)
