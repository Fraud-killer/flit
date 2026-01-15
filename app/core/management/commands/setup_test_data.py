"""
Management command to create test fixtures for stress testing.

Usage:
    python manage.py setup_test_data
"""

import uuid
from django.core.management.base import BaseCommand
from core.models import User, Organization, Application, Policy
from core import mcrypt


class Command(BaseCommand):
    help = "Create test fixtures for stress testing"

    def handle(self, *args, **options):
        self.stdout.write("Creating test fixtures...")

        user, created = User.objects.get_or_create(
            email="test@flit.io",
            defaults={
                "password": "testpassword123",
                "is_staff": True,
                "is_superuser": True,
            }
        )
        if created:
            user.set_password("testpassword123")
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Created user: {user.email}"))
        else:
            self.stdout.write(f"User already exists: {user.email}")

        org, created = Organization.objects.get_or_create(
            name="Test Organization",
            defaults={"owner": user}
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"Created organization: {org.name}"))
        else:
            self.stdout.write(f"Organization already exists: {org.name}")

        app_id = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
        secret_key = "test-secret-key-12345"
        visit_sdk_key = "test-visit-sdk-key-12345"

        app, created = Application.objects.get_or_create(
            id=app_id,
            defaults={
                "name": "Test Application",
                "organization": org,
                "secret_key": mcrypt.encrypt(secret_key),
                "visit_sdk_key": mcrypt.encrypt(visit_sdk_key),
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"Created application: {app.name}"))
        else:
            self.stdout.write(f"Application already exists: {app.name}")

        policy, created = Policy.objects.get_or_create(
            application=app,
            defaults={
                "aml_cft_limit": "50000 USD",
                "device_validity_days": 30,
                "kyc_level_limits": {
                    "level_1": {"daily_limit": "1000 USD", "single_limit": "500 USD"},
                    "level_2": {"daily_limit": "10000 USD", "single_limit": "5000 USD"},
                    "level_3": {"daily_limit": "100000 USD", "single_limit": "50000 USD"},
                }
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"Created policy for: {app.name}"))
        else:
            self.stdout.write(f"Policy already exists for: {app.name}")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write(self.style.SUCCESS("TEST FIXTURES CREATED SUCCESSFULLY"))
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write("")
        self.stdout.write(f"Application ID:  {app_id}")
        self.stdout.write(f"Secret Key:      {secret_key}")
        self.stdout.write(f"Visit SDK Key:   {visit_sdk_key}")
        self.stdout.write("")
        self.stdout.write("Use these credentials in your stress tests:")
        self.stdout.write(f"  --app-id {app_id}")
        self.stdout.write(f"  --secret {secret_key}")
        self.stdout.write("")
