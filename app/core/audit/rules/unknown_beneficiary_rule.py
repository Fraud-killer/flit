from asgiref.sync import sync_to_async
from django.utils import timezone
from devkit.message import Message

from core.audit.events import TransactionEvent
from core.services.money_out import BeneficiaryControl, BeneficiaryTrust

from .base_rule import BaseRule, Maturity, RuleKind


class UnknownBeneficiaryRule(BaseRule):
    """
    Refuses a credential paying from an account to someone it has no history of.

    The question is about the triple, not the account. A settlement credential
    has a small, stable set of destinations for each merchant, so a stolen one
    is visible on its first transfer: the account is normal and the amount is
    normal, and that credential has never paid this beneficiary from this
    account. Not every business looks like that, so this is opt-in through
    Policy.beneficiary_control, and it can run in Policy.shadow_rules.
    """

    kind = RuleKind.CONTROL
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_outflow_breaker.py::TestUnknownBeneficiary"

    @property
    def applies(self):
        return (
            isinstance(self.event, TransactionEvent)
            and self.event.type == "debit"
            and BeneficiaryControl.for_policy(self.policy) is not None
        )

    def blocks_on_failure(self):
        control = BeneficiaryControl.for_policy(self.policy)
        return control is not None and control.fail == "block"

    def _value(self, name):
        from core.audit.recorder import AuditRecorder
        return AuditRecorder.value(self.event, name)

    async def perform(self):
        control = BeneficiaryControl.for_policy(self.policy)
        initiator = self._value("initiator_id")
        counterparty = self._value("counterparty_id")
        client_id = self.event.account_id

        if not (initiator and counterparty and client_id):
            return Message(
                code="beneficiary_unverified",
                path="counterparty_id",
                text="This debit does not say who initiated it, from where, or to whom",
                context=dict(force_review=True, score=0.0),
            )

        link = await sync_to_async(BeneficiaryTrust.link)(
            self.application.id, initiator=initiator, client_id=client_id,
            counterparty=counterparty, bank=self._value("counterparty_bank"),
        )

        if link is not None and link.trusted(cooling=control.cooling, now=timezone.now()):
            return None

        return Message(
            code="unknown_beneficiary",
            path="counterparty_id",
            text="This credential has no trusted history of paying this beneficiary from this account",
            context=dict(
                hard_block=True,
                seen_before=link is not None,
                revoked=bool(link and link.revoked_at),
            ),
        )
