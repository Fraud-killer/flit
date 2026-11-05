"""
Walk the audit chain and say whether it still holds.

The chain only proves anything if somebody checks it. Run nightly:

    python manage.py verify_audit_chain            # every application
    python manage.py verify_audit_chain --app ID   # one
    python manage.py verify_audit_chain --days 7   # recent rows only

Exit status is non-zero when a break is found, so a scheduler can alert on it.
"""

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.audit.logger import AuditLogger
from core.models import Application


class Command(BaseCommand):
    help = "Verify the tamper-evident hash chain of the audit log"

    def add_arguments(self, parser):
        parser.add_argument("--app", dest="application_id", help="One application's chain")
        parser.add_argument("--days", type=int, default=None, help="Only rows from the last N days")
        parser.add_argument("--json", action="store_true", help="Machine-readable output")

    def handle(self, *args, **options):
        from core.services.job_lock import JobLock, JobLocked

        try:
            with JobLock.hold("verify_audit_chain"):
                return self.run(*args, **options)
        except JobLocked as held:
            self.stdout.write(self.style.WARNING(f"Skipped: {held}"))
            return

    def run(self, *args, **options):
        since = None
        if options["days"]:
            since = timezone.now() - timedelta(days=options["days"])

        if options["application_id"]:
            applications = list(Application.objects.filter(id=options["application_id"]))
            if not applications:
                raise CommandError(f"No application {options['application_id']}")
        else:
            applications = list(Application.objects.all())

        broken = []
        reports = []

        for application in applications:
            report = AuditLogger.verify_chain_integrity(
                application_id=application.id, start_date=since,
            )
            report["application_id"] = str(application.id)
            report["application"] = application.name
            reports.append(report)

            if not report["chain_valid"]:
                broken.append(report)

        if options["json"]:
            import json
            self.stdout.write(json.dumps(reports, indent=2, default=str))
        else:
            for report in reports:
                status = "ok" if report["chain_valid"] else "BROKEN"
                self.stdout.write(
                    f"{report['application']:<30} {report['total_entries']:>8} rows  {status}"
                )
                for entry in report["invalid_entries"][:10]:
                    self.stdout.write(f"    {entry}")

        if broken:
            raise CommandError(f"{len(broken)} chain(s) broken")
