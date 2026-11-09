from asgiref.sync import sync_to_async
from django.utils import timezone
from devkit.message import Message

from core.audit.events import TransactionEvent
from core.models import OutflowTrip
from core.services.money_out import BeneficiaryTrust
from core.services.outflow_window import (
    APPLICATION_SCOPE_VALUE, FAIL_BLOCK, OutflowLimits, OutflowWindow, SCOPE_KEYS, to_minor,
)

from .base_rule import BaseRule, Maturity, RuleKind


class OutflowBreakerRule(BaseRule):
    """
    Caps the value leaving through one credential, channel or application.

    Every other limit is per account, so a drain spread across accounts never
    meets one. A breach is a hard block: a clean history says nothing about
    whether a credential has been taken, and it must not soften this. The
    latch that holds the scope stopped is set after the decision, by
    core.services.money_out, so a shadow run stops nothing.

    A debit to a beneficiary the credential has no trusted history with is
    also counted in the initiator_untrusted scope, which has its own, smaller
    limits. A trip there stops only such debits.
    """

    kind = RuleKind.CONTROL
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_outflow_breaker.py::TestOutflowBreaker"

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and self.event.type == "debit"
            and bool(getattr(self.policy, "outflow_limits", None))
            # A replay of history must not spend tonight's limits.
            and getattr(self.scope, "measures_outflow", False)
        )

    def blocks_on_failure(self):
        limits = OutflowLimits.for_policy(self.policy)
        return limits is not None and limits.fail == FAIL_BLOCK

    def _value(self, name):
        from core.audit.recorder import AuditRecorder
        return AuditRecorder.value(self.event, name)

    def _scopes(self, limits, now):
        scopes = [("application", APPLICATION_SCOPE_VALUE)]
        for kind, name in (("initiator", "initiator_id"), ("channel", "channel")):
            value = self._value(name)
            if value:
                scopes.append((kind, str(value)))

        initiator = self._value("initiator_id")
        if initiator and limits.watches_untrusted and not BeneficiaryTrust.trusted(
            self.policy, initiator=initiator, client_id=self.event.account_id,
            counterparty=self._value("counterparty_id"), bank=self._value("counterparty_bank"), now=now,
        ):
            scopes.append(("initiator_untrusted", str(initiator)))
        return scopes

    def _unmeasured(self, reason, *, force_block):
        action = dict(hard_block=True) if force_block else dict(force_review=True)
        return Message(
            code="outflow_unmeasured",
            path="amount",
            text="This debit could not be measured against the outflow limits",
            context=dict(reason=reason, score=0.0, **action),
        )

    async def perform(self):
        limits = OutflowLimits.for_policy(self.policy)
        now = timezone.now()
        scopes = await sync_to_async(self._scopes)(limits, now)
        refuse = limits.fail == FAIL_BLOCK

        tripped = await sync_to_async(self._open_trip)(scopes)
        if tripped is not None:
            return Message(
                code="outflow_trip_active",
                path="initiator_id",
                text="Outflow is stopped for this scope until a person releases it",
                context=dict(
                    hard_block=True, trip_id=str(tripped.id),
                    scope_kind=tripped.scope_kind, scope_value=tripped.scope_value,
                ),
            )

        amount = self.event.amount
        if type(amount) not in (int, float) or amount <= 0:
            return self._unmeasured("amount", force_block=refuse)
        if self.event.currency_code != limits.currency:
            return self._unmeasured("currency", force_block=refuse)

        messages = []
        per_credential = limits.raw.get(SCOPE_KEYS["initiator"]) or limits.watches_untrusted
        if per_credential and not self._value("initiator_id"):
            # An integration gap, not an attacker: review it, and measure the rest.
            messages.append(self._unmeasured("initiator", force_block=False))

        reservation, breaches = await sync_to_async(OutflowWindow.reserve)(
            self.application.id, scopes, to_minor(amount),
            {kind: limits.limits_for(kind, now) for kind, _ in scopes},
            now,
        )
        self.scope.outflow_reservation = reservation

        if breaches:
            messages.append(Message(
                code="outflow_limit_exceeded",
                path="amount",
                text="This transfer would take outflow over a configured limit",
                context=dict(hard_block=True, breaches=breaches, currency_code=limits.currency),
            ))

        return messages

    def _open_trip(self, scopes):
        for kind, value in scopes:
            trip = OutflowTrip.objects.filter(
                application_id=self.application.id, scope_kind=kind, scope_value=value,
                released_at__isnull=True,
            ).first()
            if trip is not None:
                return trip
        return None
