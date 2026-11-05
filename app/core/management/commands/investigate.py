"""
Run one investigation now, from the shell.

    python manage.py investigate --application NAME --case ID
    python manage.py investigate --application NAME --playbook account_review --client-id C123
    python manage.py investigate --application NAME --playbook campaign_review --ip 41.58.100.7

Runs synchronously and prints the report. Writes follow the application's
agent policy; pass --mode propose to be sure nothing executes.
"""

import json

from django.core.management.base import BaseCommand, CommandError

from core.models import Application, Case, AgentMode


class Command(BaseCommand):
    help = "Run one Agent FLIT investigation and print its report"

    def add_arguments(self, parser):
        parser.add_argument("--application", required=True, help="Application name")
        parser.add_argument("--playbook", default="investigate_case")
        parser.add_argument("--case", dest="case_id")
        parser.add_argument("--client-id")
        parser.add_argument("--device-id")
        parser.add_argument("--ip")
        parser.add_argument("--hours", type=int)
        parser.add_argument("--mode", choices=AgentMode.VALUES)
        parser.add_argument("--json", action="store_true", help="Print the whole investigation as JSON")

    def handle(self, *args, **options):
        from core.agent import Investigations, InvestigationRunner, AgentGuardrails, PlaybookError
        from core.models import AgentPolicy

        if not AgentGuardrails.enabled_globally():
            raise CommandError("AGENT_ENABLED is off")

        application = Application.objects.filter(name=options["application"]).first()
        if application is None:
            raise CommandError(f"No application named {options['application']}")

        case = None
        if options["case_id"]:
            case = Case.objects.filter(id=options["case_id"], application=application).select_related("audit_log").first()
            if case is None:
                raise CommandError("No such case for this application")

        subject = {k: v for k, v in dict(
            client_id=options["client_id"], device_id=options["device_id"], ip_address=options["ip"], hours=options["hours"],
        ).items() if v}

        try:
            investigation = Investigations.open(
                application=application, playbook=options["playbook"], subject=subject, case=case, mode=options["mode"],
            )
        except PlaybookError as problem:
            raise CommandError(str(problem))

        investigation = InvestigationRunner.start(investigation)
        self.report(investigation, as_json=options["json"])
        if investigation.status == "failed":
            raise CommandError(investigation.error)

    def report(self, investigation, *, as_json=False):
        from api.serializers.agent_serializers import serialize_investigation
        if as_json:
            self.stdout.write(json.dumps(serialize_investigation(investigation, steps=True), indent=2, default=str))
            return
        self.stdout.write(f"{investigation.id}  {investigation.playbook}  {investigation.status}  mode={investigation.mode}")
        self.stdout.write(f"turns {investigation.turns}  cost ${investigation.cost_usd:.4f}")
        for step in investigation.steps.order_by("index"):
            self.stdout.write(f"  {step.index:>2}. {step.kind:<10} {step.tool:<20} {step.status:<9} {step.decision_source}")
        report = investigation.report or {}
        if report:
            self.stdout.write("")
            self.stdout.write(f"verdict: {report.get('verdict')} ({report.get('confidence')})")
            self.stdout.write(report.get("summary", ""))
            for finding in report.get("findings", []):
                verification = (finding.get("verification") or {}).get("verdict", "-")
                self.stdout.write(f"  [{finding.get('severity')}] {finding.get('title')}  ({verification})")
        if investigation.error:
            self.stdout.write(self.style.ERROR(investigation.error))
