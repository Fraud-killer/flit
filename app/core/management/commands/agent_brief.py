"""
The shift brief: what happened, what is waiting, what to look at first.

    python manage.py agent_brief --application NAME --hours 12

Runs the `shift_brief` playbook in propose mode and prints the summary.
"""

from django.core.management.base import BaseCommand, CommandError

from core.models import Application, InvestigationTrigger, AgentMode


class Command(BaseCommand):
    help = "Write the shift brief for an application"

    def add_arguments(self, parser):
        parser.add_argument("--application", required=True)
        parser.add_argument("--hours", type=int, default=12)

    def handle(self, *args, **options):
        from core.agent import Investigations, InvestigationRunner, AgentGuardrails

        if not AgentGuardrails.enabled_globally():
            raise CommandError("AGENT_ENABLED is off")
        application = Application.objects.filter(name=options["application"]).first()
        if application is None:
            raise CommandError(f"No application named {options['application']}")

        investigation = Investigations.open(
            application=application, playbook="shift_brief", subject=dict(hours=options["hours"]),
            trigger=InvestigationTrigger.SCHEDULE, mode=AgentMode.PROPOSE,
        )
        investigation = InvestigationRunner.start(investigation)
        if investigation.status != "completed":
            raise CommandError(investigation.error or investigation.status)
        self.stdout.write(investigation.summary)
        for finding in (investigation.report or {}).get("findings", []):
            self.stdout.write(f"  [{finding.get('severity')}] {finding.get('title')}")
