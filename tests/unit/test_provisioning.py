"""
Tests for onboarding a merchant.

Provisioning is the first thing anyone does with FLIT and the last thing that
gets exercised, so these cover the parts that would strand an operator: a
merchant who does not use Fingerprint, a secret that has to be captured at
the moment it is printed, and an enforcement switch that should never be
flipped by accident.
"""

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError


def provision(name="Figo", **options):
    out = StringIO()
    call_command(
        "provision_application", name, owner="ops@spendfigo.com",
        stdout=out, **options,
    )
    return out.getvalue()


class TestOnboardingWithoutFingerprint:
    def test_an_application_is_created_with_no_fingerprint_account(self, db):
        """
        FLIT ships its own browser collector, so a Fingerprint management key
        is not a dependency FLIT actually has. Requiring one here would have
        meant no merchant could be onboarded without a Fingerprint account.
        """
        from core.models import Application

        provision()
        application = Application.objects.get(name="Figo")

        assert application.secret_key
        assert application.visit_sdk_key is None
        assert application.collect_key.startswith("flit_pk_")

    def test_a_fingerprint_outage_does_not_stop_onboarding(self, db):
        from unittest.mock import patch

        from core.models import Application
        from core.services.create_application import CreateApplication

        with patch.object(
            CreateApplication, "fingerprint_enabled", classmethod(lambda cls: True),
        ), patch(
            "core.services.fingerprint.CreatePublicKey.call",
            side_effect=OSError("fingerprint down"),
        ):
            CreateApplication.call(
                name="Resilient", organization=_organization(),
            )

        assert Application.objects.filter(name="Resilient").exists()


class TestProvisioningOutput:
    def test_the_credentials_are_printed_once(self, db):
        from core import mcrypt
        from core.models import Application

        output = provision()
        application = Application.objects.get(name="Figo")

        assert str(application.id) in output
        assert mcrypt.decrypt(application.secret_key) in output
        assert "cannot be printed again" in output

    def test_it_starts_in_shadow_and_says_so(self, db):
        from core.models import Application

        output = provision()

        assert Application.objects.get(name="Figo").enforcement == "shadow"
        assert "shadow" in output

    def test_the_policy_currency_can_be_set_at_creation(self, db):
        """
        A limit in a currency the merchant does not use cannot be evaluated,
        and every decision reports a mismatch instead — which is exactly what
        the first Figo backtest ran into.
        """
        from core.models import Application

        provision(currency="USD")

        assert Application.objects.get(name="Figo").policy.aml_cft_limit == (
            "USD 10,000.00"
        )

    def test_provisioning_the_same_merchant_twice_is_refused(self, db):
        provision()

        with pytest.raises(CommandError):
            provision()


class TestEnforcementSwitch:
    def test_it_reports_what_the_shadow_period_saw(self, db):
        from core.models import Application

        provision()
        out = StringIO()
        call_command("set_enforcement", "Figo", "enforcing", stdout=out)

        assert Application.objects.get(name="Figo").is_enforcing
        assert "shadow -> enforcing" in out.getvalue()

    def test_enforcing_with_no_shadow_period_warns(self, db):
        provision()
        out = StringIO()
        call_command("set_enforcement", "Figo", "enforcing", stdout=out)

        assert "no recorded decisions" in out.getvalue()

    def test_an_unknown_application_is_an_error(self, db):
        with pytest.raises(CommandError):
            call_command("set_enforcement", "Nobody", "enforcing")

    def test_it_can_be_moved_back_to_shadow(self, db):
        from core.models import Application

        provision()
        call_command("set_enforcement", "Figo", "enforcing", stdout=StringIO())
        call_command("set_enforcement", "Figo", "shadow", stdout=StringIO())

        assert not Application.objects.get(name="Figo").is_enforcing


def _organization():
    from core.models import Organization, User

    user = User.objects.filter(email="org@flit.io").first() or (
        User.objects.create_user(email="org@flit.io", password="x" * 12)
    )
    organization, _ = Organization.objects.get_or_create(
        name="Resilient Org", defaults=dict(owner=user),
    )
    return organization
