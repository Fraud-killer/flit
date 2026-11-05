"""
Evaluate every active monitor; fire the ones whose condition is met.

    python manage.py run_monitors            # every five minutes

Fired monitors alert, tell the webhook, and may queue an investigation.
"""

from django.core.management.base import BaseCommand

from core.models import Application


class Command(BaseCommand):
    help = "Evaluate Agent FLIT monitors"

    def add_arguments(self, parser):
        parser.add_argument("--application", help="Only this application's monitors")

    def handle(self, *args, **options):
        from core.services.job_lock import JobLock, JobLocked
        from core.agent import Monitors, AgentGuardrails

        if not AgentGuardrails.enabled_globally():
            self.stdout.write("AGENT_ENABLED is off; nothing to evaluate")
            return

        application = None
        if options["application"]:
            application = Application.objects.filter(name=options["application"]).first()

        try:
            with JobLock.hold("run_monitors", stale_seconds=10 * 60):
                fired, expired = Monitors.evaluate(application=application)
        except JobLocked as held:
            self.stdout.write(self.style.WARNING(f"Skipped: {held}"))
            return

        for monitor in fired:
            self.stdout.write(f"fired   {monitor.application.name:<24} {monitor.name} ({monitor.metric}={monitor.fired_value})")
        self.stdout.write(f"fired {len(fired)}, expired {len(expired)}")
