"""
Read the open cases with a model, in shadow or for real.

    python manage.py triage --application "Figo"              # propose, store, act on nothing
    python manage.py triage --application "Figo" --apply      # also auto-clear, under the guardrails
    python manage.py triage --application "Figo" --report     # how proposals have agreed with humans
    python manage.py triage --application "Figo" --reset-breaker

Off unless TRIAGE_ENABLED is set. Proposals are stored on the case beside
the human's eventual verdict; `--report` is the measurement, and `--apply`
only clears when that measurement has earned it.
"""

import json

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.models import Application, Case, CaseStatus
from core.triage import CaseTriage, TriageGuardrails


class Command(BaseCommand):
    help = "Propose verdicts for open cases with a model; act only under the guardrails"

    def add_arguments(self, parser):
        parser.add_argument("--application", required=True, help="Application name")
        parser.add_argument("--limit", type=int, default=100)
        parser.add_argument("--apply", action="store_true", help="Auto-clear cases the guardrails allow")
        parser.add_argument("--report", action="store_true", help="Measure proposals against human verdicts")
        parser.add_argument("--reset-breaker", action="store_true", help="Re-enable auto-clearing after a trip")
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        from core.services.job_lock import JobLock, JobLocked

        try:
            with JobLock.hold("triage"):
                return self.run(*args, **options)
        except JobLocked as held:
            self.stdout.write(self.style.WARNING(f"Skipped: {held}"))
            return

    def run(self, *args, **options):
        application = Application.objects.filter(name=options["application"]).first()
        if not application:
            raise CommandError(f"No application named {options['application']!r}")

        if options["reset_breaker"]:
            TriageGuardrails.reset(application)
            self.stdout.write("Circuit breaker reset; auto-clearing may resume under the guardrails.")
            return

        if options["report"]:
            measured = TriageGuardrails.measure(application)
            allowed, reason = TriageGuardrails.may_auto_clear(application)
            report = dict(measured, may_auto_clear=allowed, reason=reason,
                          breaker_tripped_at=TriageGuardrails.tripped(application))
            self.stdout.write(json.dumps(report, indent=2, default=str))
            return

        if not CaseTriage.enabled():
            raise CommandError("TRIAGE_ENABLED is not set; nothing read.")

        cases = list(
            Case.objects
            .filter(application=application, status=CaseStatus.OPEN, triage_proposal__isnull=True)
            .select_related("audit_log", "application")
            .order_by("-priority", "opened_at")[:options["limit"]]
        )

        may_clear, why = TriageGuardrails.may_auto_clear(application) if options["apply"] else (False, "shadow")
        proposed = cleared = unavailable = 0

        for case in cases:
            proposal = CaseTriage.propose(case)
            case.triage_proposal = proposal
            case.triage_at = timezone.now()
            fields = ["triage_proposal", "triage_at"]

            if proposal.get("unavailable"):
                unavailable += 1

            if (
                options["apply"] and may_clear and proposal["verdict"] == "cleared"
                and not proposal.get("unavailable")
            ):
                case.triage_auto_closed = True
                case.save(update_fields=fields + ["triage_auto_closed"])
                case.resolve(status=CaseStatus.CLEARED, note=f"Auto-cleared by triage: {proposal['reason']}")
                TriageGuardrails.record_auto_clear(application)
                cleared += 1
                if not TriageGuardrails.may_auto_clear(application)[0]:
                    may_clear = False
            else:
                case.save(update_fields=fields)

            proposed += 1

        self.stdout.write(
            f"proposed {proposed}, auto-cleared {cleared}, unavailable {unavailable}"
            + ("" if options["apply"] else " (shadow)")
            + (f"; auto-clear: {why}" if options["apply"] else "")
        )
