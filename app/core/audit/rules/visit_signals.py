import logging
from devkit.checks import is_present


logger = logging.getLogger(__name__)


async def fetch_visit_signals(rule):
    """
    Fingerprint visit data for the rule's event, or None.

    Intelligence rules only enrich the decision, so a Fingerprint outage or
    missing API key must not fail the whole audit.
    """
    visit_id = getattr(rule.event, "visit_id", None)
    if not is_present(visit_id):
        return None

    try:
        return await rule.scope.fetch_visit(visit_id)
    except Exception as error:
        logger.warning(f"{type(rule).__name__}: could not fetch visit {visit_id}: {error}")
        return None


def event_value(event, name):
    value = getattr(event, name, None)
    return value if is_present(value) else None
