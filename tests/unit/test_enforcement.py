"""
Tests for shadow mode.

A fraud tool that blocks on its first day turns away real customers on
thresholds nobody has measured against that merchant's traffic. Shadow is how
a merchant finds out what FLIT would have done to their own customers before
letting it do anything.

The property that matters most is not that shadow suppresses actions — it is
*which field* it suppresses. An integration is written as
`if (decision.should_block) reject()`. If shadow left that field true and
signalled itself somewhere else, the first integration that forgot the second
check would block real customers.
"""

import pytest

from tests.unit.test_signup_defence import CURL, register


LISTED_EVM = "0x7F367cC41522cE07553e823bf3be79A889DEbe1B"


@pytest.fixture
def shadow_application(application):
    application.enforcement = "shadow"
    application.save(update_fields=["enforcement"])
    return application


def blocking_signup(app, client_id):
    """A registration FLIT decides against: bot client, reserved domain."""
    return register(
        app,
        email=f"{client_id}@example.com",
        ip_address="193.200.229.243",
        user_agent=CURL,
        client_id=client_id,
    )


class TestDefaults:
    def test_a_new_application_starts_in_shadow(self, db):
        from core.models import User, Organization, Application, Enforcement

        user = User.objects.create_user(email="new@flit.io", password="x" * 12)
        organization = Organization.objects.create(name="New Org", owner=user)
        app = Application.objects.create(name="New App", organization=organization)

        assert app.enforcement == Enforcement.SHADOW
        assert not app.is_enforcing


class TestShadowSuppressesActions:
    def test_the_field_an_integration_branches_on_is_false(
        self, shadow_application, no_geoip,
    ):
        result = blocking_signup(shadow_application, "shadow_1")

        assert result.should_block is False
        assert result.should_challenge is False

    def test_but_the_decision_is_still_reported(
        self, shadow_application, no_geoip,
    ):
        result = blocking_signup(shadow_application, "shadow_2")

        assert result.would_block or result.would_challenge
        assert result.risk_score > 0
        assert result.enforcement == "shadow"

    def test_the_same_event_acts_when_enforcing(self, application, no_geoip):
        result = blocking_signup(application, "enforcing_1")

        assert result.would_block or result.would_challenge
        assert result.should_block == result.would_block
        assert result.should_challenge == result.would_challenge

    def test_review_still_happens_in_shadow(self, shadow_application, no_geoip):
        """
        A case in a queue costs a reviewer's attention, not a customer's
        signup — and reviewing is how the labels arrive that make enforcing
        defensible later.
        """
        from core.models import Case

        blocking_signup(shadow_application, "shadow_3")

        assert Case.objects.filter(application=shadow_application).exists()

    def test_a_sanctions_hit_is_also_suppressed_in_shadow(
        self, shadow_application, no_geoip,
    ):
        """
        Deliberate, and worth stating: shadow means shadow. A merchant who
        needs sanctions enforced from day one turns enforcement on — FLIT
        does not quietly decide some rules are too important to shadow.
        """
        from tests.unit.test_sanctions import load
        from tests.unit.test_crypto import transfer, codes

        load()
        result = transfer(
            shadow_application, type="debit", client_id="sanctioned_1",
            counterparty_address=LISTED_EVM,
        )

        assert "sanctioned_address" in codes(result)
        assert result.should_block is False
        assert result.would_block is True


class TestRecordedHistory:
    def test_shadow_records_the_decision_it_would_have_enforced(
        self, shadow_application, no_geoip,
    ):
        """
        The whole point of shadow is measuring it afterwards. If history
        recorded the suppressed action rather than the decision, a shadow
        period would teach nothing.
        """
        from core.models import AuditLog

        blocking_signup(shadow_application, "shadow_4")
        log = AuditLog.objects.filter(actor_id="shadow_4").first()

        assert log.context["should_block"] is True
        assert log.context["enforcement"] == "shadow"

    def test_an_unrecognised_enforcement_value_is_treated_as_shadow(
        self, application, no_geoip,
    ):
        """
        A misconfiguration must suppress actions rather than take them. Only
        the exact string "enforcing" enables enforcement; anything else — a
        typo, a half-finished migration, a value from a newer version — falls
        back to shadow.
        """
        application.enforcement = "enforcingg"
        application.save(update_fields=["enforcement"])

        result = blocking_signup(application, "typo_1")

        assert result.should_block is False
        assert result.would_block or result.would_challenge
