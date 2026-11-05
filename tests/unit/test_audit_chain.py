"""
The audit chain has to notice the tampering that matters.

The hash used to cover the envelope — who, when, which action — and not the
decision. A risk score edited after the fact, a factor removed from the list,
a `should_block` flipped in the context: all verified clean. Now the hash
covers them, old rows still verify against the hash they were written with,
and there is a command that actually runs the check.
"""

import pytest


def write(application, **overrides):
    from core.audit.logger import AuditLogger
    from core.audit.models import AuditLogCategory, AuditLogLevel

    fields = dict(
        level=AuditLogLevel.WARNING,
        category=AuditLogCategory.TRANSACTION,
        action="transaction_debit",
        actor_type="client",
        actor_id="user_1",
        application_id=application.id,
        risk_score=0.82,
        risk_factors=["velocity_exceeded_per_hour", "datacenter_ip"],
        context=dict(should_block=True, factors=[dict(code="datacenter_ip", weight=0.3)]),
        user_agent="curl/8.20.0",
    )
    fields.update(overrides)
    return AuditLogger.log(**fields)


class TestWhatTheHashCovers:
    def test_a_fresh_row_verifies(self, application):
        log = write(application)
        assert log.verify_integrity()

    @pytest.mark.parametrize("field, value", [
        ("risk_score", 0.1),
        ("risk_factors", ["datacenter_ip"]),
        ("context", dict(should_block=False)),
        ("user_agent", "Mozilla/5.0"),
        ("device_fingerprint", "someone_elses_device"),
        ("action", "transaction_credit"),
        ("actor_id", "user_2"),
    ])
    def test_changing_the_decision_breaks_verification(self, application, field, value):
        log = write(application)
        setattr(log, field, value)
        assert not log.verify_integrity()

    def test_reordering_context_keys_does_not(self, application):
        """The same decision is the same bytes however the dict was built."""
        log = write(application, context=dict(a=1, b=dict(y=2, x=1)))
        log.context = dict(b=dict(x=1, y=2), a=1)
        assert log.verify_integrity()

    def test_labels_stay_outside_the_chain(self, application):
        """A label arrives after the event; recording it must not break history."""
        from django.utils import timezone

        log = write(application)
        log.label = "fraud"
        log.labeled_at = timezone.now()
        log.save()
        assert log.verify_integrity()


class TestOldRowsStillVerify:
    def test_a_version_one_hash_is_accepted(self, application):
        log = write(application)
        # Re-hash the way the previous release did and store that.
        log.entry_hash = log._compute_hash(version=1)
        log.save(update_fields=["entry_hash"])
        log.refresh_from_db()

        assert log.verify_integrity()

    def test_but_tampering_with_a_version_one_row_is_still_caught(self, application):
        log = write(application)
        log.entry_hash = log._compute_hash(version=1)
        log.action = "transaction_credit"
        assert not log.verify_integrity()


class TestTheChain:
    def test_rows_chain_per_application(self, application, second_application):
        first = write(application)
        other = write(second_application)
        second = write(application)

        assert first.previous_hash is None
        assert second.previous_hash == first.entry_hash
        assert other.previous_hash is None

    def test_the_verifier_walks_a_clean_chain(self, application):
        from core.audit.logger import AuditLogger

        for _ in range(3):
            write(application)

        report = AuditLogger.verify_chain_integrity(application_id=application.id)
        assert report["chain_valid"]
        assert report["total_entries"] == 3

    def test_the_verifier_catches_an_edited_row(self, application):
        from core.audit.logger import AuditLogger
        from core.models import AuditLog

        write(application)
        target = write(application)
        write(application)

        AuditLog.objects.filter(id=target.id).update(risk_score=0.0)

        report = AuditLogger.verify_chain_integrity(application_id=application.id)
        assert not report["chain_valid"]
        assert any(e["id"] == str(target.id) for e in report["invalid_entries"])


class TestTheCommand:
    def test_a_clean_chain_exits_zero(self, application):
        from io import StringIO
        from django.core.management import call_command

        write(application)
        out = StringIO()
        call_command("verify_audit_chain", stdout=out)

        assert "ok" in out.getvalue()

    def test_a_broken_chain_fails_the_command(self, application):
        from io import StringIO
        from django.core.management import call_command
        from django.core.management.base import CommandError
        from core.models import AuditLog

        target = write(application)
        AuditLog.objects.filter(id=target.id).update(risk_score=0.0)

        with pytest.raises(CommandError):
            call_command("verify_audit_chain", stdout=StringIO())
