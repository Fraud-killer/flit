"""
Create a merchant application and print its credentials.

    python manage.py provision_application "Figo" --owner ops@spendfigo.com \
        --currency USD

The secret key is shown once and never again: only its encrypted form is
stored, and nothing can print it back. Capture it into the merchant's
environment at the moment it appears.

Applications are created in shadow. Moving one to enforcing is a separate,
deliberate command — see `set_enforcement`.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from core import mcrypt
from core.models import Application, Enforcement, Organization, User
from core.services.create_application import CreateApplication


class Command(BaseCommand):
    help = "Create an application, its organization and its API credentials"

    def add_arguments(self, parser):
        parser.add_argument("name", help="Merchant name, e.g. Figo")
        parser.add_argument(
            "--owner", required=True, help="Email of the owning user",
        )
        parser.add_argument(
            "--organization",
            help="Organization name (defaults to the merchant name)",
        )
        parser.add_argument(
            "--currency",
            help=(
                "Currency for the AML limit, e.g. USD. A policy limit in a "
                "currency the merchant does not use cannot be evaluated at "
                "all, and every decision reports a mismatch instead."
            ),
        )
        parser.add_argument(
            "--aml-limit",
            default="10,000.00",
            help="AML limit amount, paired with --currency (default 10,000.00)",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        name = options["name"]

        if Application.objects.filter(name=name).exists():
            raise CommandError(f"An application named {name!r} already exists")

        user = User.objects.filter(email=options["owner"]).first()

        if not user:
            # No password: this account exists to own the organization, and
            # a console login is granted separately if anyone needs one.
            user = User.objects.create_user(email=options["owner"], password=None)
            user.set_unusable_password()
            user.save(update_fields=["password"])

        organization, _ = Organization.objects.get_or_create(
            name=options["organization"] or name, defaults=dict(owner=user),
        )

        application = CreateApplication.call(
            name=name, organization=organization,
        )

        if options["currency"]:
            policy = application.policy
            policy.aml_cft_limit = f"{options['currency']} {options['aml_limit']}"
            policy.save(update_fields=["aml_cft_limit"])

        secret_key = mcrypt.decrypt(application.secret_key)

        self.stdout.write(self.style.SUCCESS(f"Created {name}"))
        self.stdout.write("")
        self.stdout.write("  FLIT_APPLICATION_ID  " + str(application.id))
        self.stdout.write("  FLIT_SECRET_KEY      " + secret_key)
        self.stdout.write("  collect key          " + application.collect_key)
        self.stdout.write("")
        self.stdout.write(f"  enforcement          {application.enforcement}")
        self.stdout.write(
            f"  AML limit            {application.policy.aml_cft_limit}"
        )
        self.stdout.write("")
        self.stdout.write(
            "The secret key is not stored in a recoverable form and cannot be "
            "printed again. Copy it now."
        )

        if application.enforcement == Enforcement.SHADOW:
            self.stdout.write(
                "Decisions will be recorded and acted on by nothing until you "
                "run: python manage.py set_enforcement " + name + " enforcing"
            )
