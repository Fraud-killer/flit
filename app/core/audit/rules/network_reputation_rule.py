from devkit.message import Message
from core.audit.events import SIGNAL_EVENTS
from core.services.network_reputation import NetworkReputation

from .base_rule import BaseRule, Maturity, RuleKind


class NetworkReputationRule(BaseRule):
    """
    Flags an actor other merchants have already caught.

    This is the only rule in FLIT whose evidence did not come from the
    merchant being protected. A card-testing ring that burns through one
    merchant and moves to the next arrives at the second one already known,
    which is the whole reason a shared network is worth belonging to.

    Everything about what may cross that boundary — own rows excluded,
    k-anonymity, counts never identities, contribution required to read — is
    enforced in core.services.network_reputation, not here.
    """

    kind = RuleKind.CORROBORATION
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_protection_network.py"

    @property
    def applies(self):
        return (
            isinstance(self.event, SIGNAL_EVENTS)
            and self.scope.identity_ladder is not None
            and bool(self.scope.identity_ladder.network_key_ids())
        )

    async def perform(self):
        verdict = await NetworkReputation.lookup_async(
            identity_key_ids=self.scope.identity_ladder.network_key_ids(),
            application=self.application,
        )

        if not verdict.is_reportable:
            return None

        return Message(
            code="network_fraud_history",
            path="visit_id",
            text=(
                f"{verdict.applications} other businesses have confirmed fraud "
                "or a failed challenge for this actor"
            ),
            context=dict(severity=verdict.severity, **verdict.as_context()),
        )
