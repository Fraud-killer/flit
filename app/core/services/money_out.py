"""
What happens to the money-out records once a decision has been made.

The rules decide; this acts on the decision. It has to run afterwards, because
only then is it known whether the transfer is going ahead. In shadow nothing is
stopped, so nothing is latched and the money counts as having left.
"""

import hashlib
import logging
from datetime import timedelta

from django.db import IntegrityError, transaction
from django.utils import timezone

from core.audit.logger import AuditLogger
from core.audit.models import AuditLogCategory, AuditLogLabel, AuditLogLevel
from core.models import InitiatorBeneficiary, OutflowTrip
from core.services.outflow_window import OutflowLimits, OutflowWindow


logger = logging.getLogger(__name__)


DEFAULT_COOLING_HOURS = 72
MAX_KEY_LENGTH = 255


def beneficiary_key(counterparty_id, counterparty_bank=None):
    """An account number only means something together with its bank."""
    key = f"{str(counterparty_bank or '').strip()}:{str(counterparty_id).strip()}".lower()
    return key if len(key) <= MAX_KEY_LENGTH else hashlib.sha256(key.encode()).hexdigest()


class BeneficiaryControl:
    """Policy.beneficiary_control: {"enabled": true, "cooling_hours": 72, "fail": "block"}."""

    def __init__(self, raw):
        self.cooling = timedelta(hours=raw.get("cooling_hours", DEFAULT_COOLING_HOURS))
        self.fail = raw.get("fail", "block")

    @classmethod
    def for_policy(cls, policy):
        raw = getattr(policy, "beneficiary_control", None)
        return cls(raw) if raw and raw.get("enabled") else None

    @staticmethod
    def validate(raw):
        if not isinstance(raw, dict):
            return ["must be an object"]
        problems = []
        if set(raw) - {"enabled", "cooling_hours", "fail"}:
            problems.append("keys are enabled, cooling_hours and fail")
        if not isinstance(raw.get("enabled"), bool):
            problems.append("enabled must be true or false")
        hours = raw.get("cooling_hours", DEFAULT_COOLING_HOURS)
        if type(hours) is not int or not 1 <= hours <= 24 * 90:
            problems.append("cooling_hours must be a whole number of hours, up to 90 days")
        if raw.get("fail", "block") not in ("block", "review"):
            problems.append("fail must be block or review")
        return problems


class BeneficiaryTrust:
    """Whether a credential has a trusted history of paying someone from an account."""

    @staticmethod
    def cooling(policy):
        control = BeneficiaryControl.for_policy(policy)
        return control.cooling if control else timedelta(hours=DEFAULT_COOLING_HOURS)

    @staticmethod
    def learns(policy):
        """Either control needs the links, so either one turns learning on."""
        if BeneficiaryControl.for_policy(policy) is not None:
            return True
        limits = OutflowLimits.for_policy(policy)
        return limits is not None and limits.watches_untrusted

    @staticmethod
    def link(application_id, *, initiator, client_id, counterparty, bank):
        return InitiatorBeneficiary.objects.filter(
            application_id=application_id,
            initiator_id=str(initiator), client_id=str(client_id),
            beneficiary_key=beneficiary_key(counterparty, bank),
        ).first()

    @classmethod
    def trusted(cls, policy, *, initiator, client_id, counterparty, bank, now):
        """A debit that does not say where it goes is not to anyone trusted."""
        if not (initiator and client_id and counterparty):
            return False
        link = cls.link(
            policy.application_id, initiator=initiator, client_id=client_id,
            counterparty=counterparty, bank=bank,
        )
        return link is not None and link.trusted(cooling=cls.cooling(policy), now=now)


# A trip on these means the credential itself may be in the wrong hands.
CREDENTIAL_SCOPES = ("initiator", "initiator_untrusted")


class MoneyOut:
    @classmethod
    def settle(cls, *, event, policy, scope, risk_result, reasons, audit_log, enforcing):
        """Returns webhook deliveries worth attempting now."""
        stopped = enforcing and risk_result.should_block
        reservation = getattr(scope, "outflow_reservation", None)

        if reservation is not None and stopped:
            OutflowWindow.release(reservation)

        deliveries = []
        if enforcing:
            deliveries = cls._trip(policy, reasons, audit_log)

        if not stopped:
            cls._learn(event, policy)

        return deliveries

    @classmethod
    def _trip(cls, policy, reasons, audit_log):
        application = policy.application
        limits = OutflowLimits.for_policy(policy)
        deliveries = []

        for message in reasons:
            if message.code != "outflow_limit_exceeded":
                continue
            for breach in message.context.get("breaches") or []:
                trip = cls._open_trip(application, breach, limits, audit_log)
                if trip is None:
                    continue
                if trip.scope_kind in CREDENTIAL_SCOPES:
                    cls._distrust_recent(policy, trip.scope_value)
                delivery = cls._announce(application, trip)
                if delivery is not None:
                    deliveries.append(delivery)

        return deliveries

    @staticmethod
    def _open_trip(application, breach, limits, audit_log):
        """The trip, or None if this scope is already stopped."""
        try:
            with transaction.atomic():
                return OutflowTrip.objects.create(
                    application=application,
                    scope_kind=breach["kind"], scope_value=str(breach["value"]),
                    window=breach["window"], limit_minor=breach["limit"], used_minor=breach["used"],
                    currency_code=limits.currency,
                    trigger_audit_id=audit_log.id if audit_log else None,
                )
        except IntegrityError:
            return None

    @staticmethod
    def _distrust_recent(policy, initiator):
        """
        Payees a tripped credential found during the cooling period never
        become trusted by age. A drain kept under the limit for a few nights
        would otherwise make its own mules trusted. A person can still
        approve any that turn out to be genuine.
        """
        now = timezone.now()
        InitiatorBeneficiary.objects.filter(
            application_id=policy.application_id, initiator_id=initiator,
            first_seen_at__gt=now - BeneficiaryTrust.cooling(policy),
            approved_at__isnull=True, revoked_at__isnull=True,
        ).update(revoked_at=now)

    @classmethod
    def _announce(cls, application, trip):
        from core.outbound import Webhooks

        cls._record(application, "outflow_tripped", AuditLogLevel.WARNING, trip, actor_type="system")
        return Webhooks.enqueue(application, "outflow.tripped", cls.describe(trip))

    @classmethod
    def release(cls, trip, *, user, note=""):
        """A person lets the scope move money again, from a clean window."""
        trip.released_at = timezone.now()
        trip.released_by = user
        trip.release_note = note
        trip.save(update_fields=["released_at", "released_by", "release_note"])

        OutflowWindow.reset(trip.application_id, trip.scope_kind, trip.scope_value)

        cls._record(
            trip.application, "outflow_released", AuditLogLevel.WARNING, trip,
            actor_type="user", actor_id=str(user.id),
        )
        return trip

    @staticmethod
    def _record(application, action, level, trip, *, actor_type, actor_id=None):
        try:
            AuditLogger.log(
                level=level, category=AuditLogCategory.POLICY, action=action,
                actor_type=actor_type, actor_id=actor_id,
                resource_type="outflow_trip", resource_id=str(trip.id),
                application_id=application.id,
                organization_id=getattr(application, "organization_id", None),
                context=MoneyOut.describe(trip), outcome="applied",
            )
        except Exception:
            logger.exception("Could not record %s", action)

    @staticmethod
    def describe(trip):
        return dict(
            id=str(trip.id),
            scope_kind=trip.scope_kind,
            scope_value=trip.scope_value,
            window=trip.window,
            limit=trip.limit_minor / 100,
            used=trip.used_minor / 100,
            currency_code=trip.currency_code,
            trigger_audit_id=str(trip.trigger_audit_id) if trip.trigger_audit_id else None,
            tripped_at=trip.tripped_at.isoformat(),
            released_at=trip.released_at.isoformat() if trip.released_at else None,
            released_by=str(trip.released_by_id) if trip.released_by_id else None,
            release_note=trip.release_note,
        )

    @staticmethod
    def _value(event, name):
        from core.audit.recorder import AuditRecorder
        return AuditRecorder.value(event, name)

    @classmethod
    def _learn(cls, event, policy):
        if event.type != "debit" or not BeneficiaryTrust.learns(policy):
            return

        initiator = cls._value(event, "initiator_id")
        counterparty = cls._value(event, "counterparty_id")
        client_id = event.account_id
        if not (initiator and counterparty and client_id):
            return

        now = timezone.now()
        link, created = InitiatorBeneficiary.objects.get_or_create(
            application=policy.application, initiator_id=str(initiator), client_id=str(client_id),
            beneficiary_key=beneficiary_key(counterparty, cls._value(event, "counterparty_bank")),
            defaults=dict(first_seen_at=now, last_seen_at=now, transfer_count=1),
        )
        if not created:
            from django.db.models import F
            InitiatorBeneficiary.objects.filter(id=link.id).update(
                last_seen_at=now, transfer_count=F("transfer_count") + 1,
            )

    @staticmethod
    def approve(application, entries, *, user):
        """A person vouches for these links, which also clears a revocation."""
        now = timezone.now()
        for entry in entries:
            InitiatorBeneficiary.objects.update_or_create(
                application=application,
                initiator_id=entry["initiator_id"],
                client_id=entry["client_id"],
                beneficiary_key=beneficiary_key(entry["counterparty_id"], entry.get("counterparty_bank")),
                defaults=dict(approved_at=now, approved_by=user, revoked_at=None),
            )

    @staticmethod
    def on_label(audit_log):
        """Fraud over a link ends its trust, however old or approved it was."""
        if audit_log.label not in (AuditLogLabel.FRAUD, AuditLogLabel.CHARGEBACK):
            return

        context = audit_log.context or {}
        initiator, counterparty = context.get("initiator_id"), context.get("counterparty_id")
        if not (initiator and counterparty and audit_log.actor_id):
            return

        InitiatorBeneficiary.objects.filter(
            application_id=audit_log.application_id,
            initiator_id=initiator, client_id=audit_log.actor_id,
            beneficiary_key=beneficiary_key(counterparty, context.get("counterparty_bank")),
        ).update(revoked_at=timezone.now())
