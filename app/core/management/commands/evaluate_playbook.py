"""
Measure a playbook against the cases people closed.

    python manage.py evaluate_playbook --application NAME --playbook investigate_case --sample 30

Replays the playbook in propose mode over the sample and stores agreement on
the application's agent policy. A playbook may run in auto mode only once
this shows at least 90% agreement over 20 decided cases.
"""

import json

from django.core.management.base import BaseCommand, CommandError

from core.models import Application


class Command(BaseCommand):
    help = "Evaluate an Agent FLIT playbook against closed cases"

    def add_arguments(self, parser):
        parser.add_argument("--application", required=True)
        parser.add_argument("--playbook", default="investigate_case")
        parser.add_argument("--sample", type=int, default=20)
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        from core.agent import AgentGuardrails, PlaybookError
        from core.agent.evals import PlaybookEval

        if not AgentGuardrails.enabled_globally():
            raise CommandError("AGENT_ENABLED is off")
        application = Application.objects.filter(name=options["application"]).first()
        if application is None:
            raise CommandError(f"No application named {options['application']}")

        try:
            result = PlaybookEval.run(application=application, playbook=options["playbook"], size=options["sample"])
        except PlaybookError as problem:
            raise CommandError(str(problem))

        if options["json"]:
            self.stdout.write(json.dumps(result, indent=2, default=str))
            return
        self.stdout.write(
            f"{result['playbook']}: n={result['n']} decided={result['decided']} agreed={result['agreed']} "
            f"disagreed={result['disagreed']} deferred={result['deferred']} failed={result['failed']} "
            f"agreement={result['agreement']} cost=${result['cost_usd']}"
        )
        gate = PlaybookEval.may_run_unattended(__import__("core.models", fromlist=["AgentPolicy"]).AgentPolicy.for_application(application), options["playbook"])
        self.stdout.write("may run unattended: " + ("yes" if gate else "no"))
