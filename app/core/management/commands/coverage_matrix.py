"""
Generate the detection coverage matrix.

    python manage.py coverage_matrix

Writes COVERAGE.md and coverage.json from the registered rules. Run it in CI
so the document can never drift from the software it describes.
"""

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.taxonomy import registry
from core.taxonomy.render import render


class Command(BaseCommand):
    help = "Generate the F3 detection coverage matrix from the registered rules"

    def add_arguments(self, parser):
        parser.add_argument(
            "--out", default="COVERAGE.md", help="Markdown output path",
        )
        parser.add_argument(
            "--json", dest="json_out", default=None,
            help="Also write the machine-readable matrix here",
        )
        parser.add_argument(
            "--check", action="store_true",
            help="Fail if the written file is out of date, instead of writing it",
        )

    def handle(self, *args, **options):
        unknown = registry.unknown_techniques()
        if unknown:
            raise CommandError(
                "Detectors reference technique ids F3 does not define: "
                + ", ".join(unknown)
            )

        unproven = registry.unproven()
        if unproven:
            raise CommandError(
                "Detectors claim evidence they cannot name: " + ", ".join(unproven)
            )

        data = registry.coverage()
        markdown = render(data)
        path = Path(options["out"])

        if options["check"]:
            current = path.read_text() if path.exists() else ""
            if current != markdown:
                raise CommandError(
                    f"{path} is out of date. Run: python manage.py coverage_matrix"
                )
            self.stdout.write(self.style.SUCCESS(f"{path} is up to date"))
            return

        path.write_text(markdown)
        self.stdout.write(self.style.SUCCESS(f"Wrote {path}"))

        if options["json_out"]:
            json_path = Path(options["json_out"])
            json_path.write_text(json.dumps(data, indent=2, sort_keys=True))
            self.stdout.write(self.style.SUCCESS(f"Wrote {json_path}"))

        totals = data["totals"]
        self.stdout.write(
            f"  covered {totals['covered']} / in scope {totals['in_scope']} "
            f"({round(totals['coverage_of_addressable'] * 100)}%), "
            f"measured {totals['measured']}, "
            f"out of telemetry {totals['out_of_telemetry']}"
        )
