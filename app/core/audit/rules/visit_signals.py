import logging
from devkit.checks import is_present


logger = logging.getLogger(__name__)


async def fetch_event_visit(event, scope, caller):
    """
    Fingerprint visit data for an event, or None.

    Intelligence only enriches the decision, so a Fingerprint outage or
    missing API key must not fail the whole audit.
    """
    visit_id = getattr(event, "visit_id", None)
    if not is_present(visit_id):
        return None

    try:
        return await scope.fetch_visit(visit_id)
    except Exception as error:
        logger.warning(f"{caller}: could not fetch visit {visit_id}: {error}")
        return None


async def fetch_visit_signals(rule):
    return await fetch_event_visit(rule.event, rule.scope, type(rule).__name__)


def event_value(event, name):
    value = getattr(event, name, None)
    return value if is_present(value) else None
