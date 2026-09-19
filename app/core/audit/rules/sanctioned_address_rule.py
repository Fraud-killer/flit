from asgiref.sync import sync_to_async
from devkit.message import Message

from core.audit.events import TransactionEvent
from core.intelligence import wallet_intelligence
from core.intelligence.sanctions import SanctionsList

from .base_rule import BaseRule, Maturity, RuleKind
from .visit_signals import event_value


@sync_to_async
def _screen(addresses):
    """Which of these addresses are on the list, and the list's own state."""
    status = SanctionsList.status()
    hits = [address for address in addresses if SanctionsList.contains(address)]
    return hits, status


class SanctionedAddressRule(BaseRule):
    """
    Screens wallet addresses against the OFAC SDN list.

    A control, not a detection. It does not describe a fraud technique and it
    is not scored against F3 coverage: it is a legal obligation that happens
    to be cheap to partially discharge, because OFAC publishes the addresses
    for free.

    Two things it deliberately does not claim. It is an exact-match check, so
    an address one hop from a sanctioned one is invisible to it — indirect
    exposure is what Chainalysis, TRM and Elliptic are for, and a fintech with
    real obligations should buy one. And a hit here is a reason to stop and
    look, not a determination: the SDN list contains addresses, and an address
    is not a person.

    The failure mode gets as much care as the hit. If the list is not loaded,
    screening is not happening — and a compliance check that quietly does
    nothing is worse than one that is absent, because it looks like coverage.
    So an unloaded or stale list is reported on the decision itself.
    """

    kind = RuleKind.CONTROL
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_sanctions.py::TestSanctionedAddressRule"

    @property
    def addresses(self):
        return [
            address for address in (
                event_value(self.event, "counterparty_address"),
                event_value(self.event, "wallet_address"),
            )
            if address
        ]

    @property
    def applies(self):
        return isinstance(self.event, TransactionEvent) and bool(self.addresses)

    async def perform(self):
        hits, status = await _screen(self.addresses)

        if hits:
            return Message(
                code="sanctioned_address",
                path="counterparty_address",
                text="Address appears on the OFAC SDN list",
                context=dict(
                    addresses=[wallet_intelligence.redact(a) for a in hits],
                    list_loaded_at=status.get("loaded_at"),
                    list_count=status.get("count"),
                    severity=1.0,
                ),
            )

        if not status["loaded"]:
            # Reported, never scored. Screening did not happen, and the
            # decision should say so rather than imply a clean result.
            return Message(
                code="sanctions_screening_unavailable",
                path="counterparty_address",
                text=(
                    "No sanctions list is loaded, so this address was not "
                    "screened. Run: python manage.py refresh_sanctions"
                ),
                context=dict(score=0.0),
            )

        if status["stale"]:
            return Message(
                code="sanctions_list_stale",
                path="counterparty_address",
                text=(
                    f"Sanctions list is {status['age_days']} days old; "
                    "OFAC updates the SDN list several times a month"
                ),
                context=dict(age_days=status["age_days"], score=0.0),
            )

        return None
