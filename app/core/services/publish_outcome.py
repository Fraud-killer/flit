"""
Publishing a merchant's ground truth to the shared protection network.

The single choke point where a label becomes network knowledge. A decision is
labelled in two places — a reviewer closing a case, and a merchant reporting
an outcome through the API — and both come through here, so there is one
answer to "what does the network learn, and when".
"""

import logging

from core.audit.models import AuditLogLabel
from core.services.network_reputation import NetworkReputation


logger = logging.getLogger(__name__)


# A chargeback is fraud that took longer to surface; a false positive is a
# merchant telling us an actor was fine. Both are ground truth worth sharing.
LABEL_OUTCOMES = {
    AuditLogLabel.FRAUD: "fraud",
    AuditLogLabel.CHARGEBACK: "fraud",
    AuditLogLabel.LEGIT: "legit",
    AuditLogLabel.FALSE_POSITIVE: "legit",
}


class PublishOutcome:
    @classmethod
    def call(cls, *, audit_log, application):
        """Record what this merchant now knows about the keys in a decision."""
        outcome = LABEL_OUTCOMES.get(getattr(audit_log, "label", None))

        if not outcome:
            return 0

        identity_key_ids = (audit_log.context or {}).get("identity_key_ids") or []

        if not identity_key_ids:
            # Decisions recorded before the identity ladder existed carry no
            # keys. Nothing to attribute, and nothing to fix.
            return 0

        try:
            return NetworkReputation.record(
                identity_key_ids=identity_key_ids,
                application=application,
                outcome=outcome,
            )
        except Exception:
            # Labelling must succeed whether or not the network does.
            logger.warning("Could not publish outcome to network", exc_info=True)
            return 0
