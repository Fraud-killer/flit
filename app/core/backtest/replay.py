"""
Replays historical transactions through FLIT's real rules.

Two things make a replay honest:

**The clock moves with the data.** Every rule asks what time it is —
velocity windows, dormancy, device first-seen. Replaying yesterday's payments
against today's clock would silently disable most of them, so the replay
freezes `timezone.now()` at each event's own timestamp.

**Labels arrive late, as they do in life.** A chargeback lands weeks after
the payment. Applying labels the instant a transaction is replayed would let
MuleNetworkRule see fraud that had not been reported yet, and flatter the
results. Labels are queued and applied once the simulated clock passes the
reporting delay.
"""

import logging
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

from asgiref.sync import async_to_sync
from django.utils import timezone

from core.models import AuditLog, DeviceIdentity
from core.models.device_identity import DeviceIdentitySource
from core.audit.auditor import Auditor
from core.audit.events import TransactionEvent
from core.backtest.mapping import MappingError


logger = logging.getLogger(__name__)

DEFAULT_LABEL_DELAY_DAYS = 7


@contextmanager
def frozen_time(moment):
    """Make `timezone.now()` return the moment being replayed."""
    with patch("django.utils.timezone.now", return_value=moment):
        yield


class Replay:
    def __init__(self, *, application, mapping, label_delay_days=DEFAULT_LABEL_DELAY_DAYS, on_progress=None):
        self.application = application
        self.mapping = mapping
        self.label_delay = timedelta(days=label_delay_days)
        self.on_progress = on_progress

        self.results = []
        self.skipped = []
        self.pending_labels = []

    def run(self, rows, limit=None):
        prepared = self.prepare(rows, limit=limit)

        # Replaying out of order would corrupt every history-based rule.
        prepared.sort(key=lambda item: item.timestamp)

        for index, item in enumerate(prepared, start=1):
            self.apply_due_labels(item.timestamp)
            self.replay_one(item)

            if self.on_progress and index % 100 == 0:
                self.on_progress(index, len(prepared))

        # Apply whatever is left, so the report counts every label.
        self.apply_due_labels(timezone.now() + timedelta(days=3650))

        return self.results

    def prepare(self, rows, limit=None):
        prepared = []

        for number, row in enumerate(rows, start=1):
            if limit and len(prepared) >= limit:
                break

            try:
                prepared.append(self.mapping.read(row))
            except (MappingError, ValueError, TypeError) as error:
                self.skip(number, f"unreadable row: {error}")

        return prepared

    def replay_one(self, item):
        event = TransactionEvent(**item.attributes)

        with frozen_time(item.timestamp):
            errors = event.verify(self.application.policy)

            if errors:
                codes = sorted({error.code for error in errors})
                return self.skip(item.attributes.get("id"), f"invalid event: {codes}")

            # The device has to be resolved before the rules run, or the
            # device graph rules cannot see it.
            identity = self.resolve_device(item) if item.device_id else None

            result = async_to_sync(Auditor.audit)(
                event,
                self.application.policy,
                send_alerts=False,
                device_identity=identity,
            )

        self.results.append(dict(
            event_id=item.attributes.get("id"),
            client_id=item.attributes.get("client_id"),
            timestamp=item.timestamp,
            audit_id=result.audit_id,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            should_block=result.should_block,
            should_review=result.should_review,
            factors=[code for code in result.factors],
            label=item.label,
        ))

        if item.label and result.audit_id:
            self.pending_labels.append((item.timestamp + self.label_delay, result.audit_id, item.label))

    def resolve_device(self, item):
        """
        Exports carry a device identifier of their own rather than a
        Fingerprint visit, so the identity is resolved from that directly.
        """
        from core.services.resolve_device_identity import ResolveDeviceIdentity
        from devkit.struct import Struct

        visit = Struct(
            fingerprint=str(item.device_id),
            source=DeviceIdentitySource.FLIT,
            device_signals={},
            ip=item.attributes.get("ip_address"),
            country=None,
            country_code=None,
        )

        return ResolveDeviceIdentity.call(
            visit=visit,
            application=self.application,
            client_id=item.attributes.get("client_id"),
        )

    def apply_due_labels(self, now):
        due = [entry for entry in self.pending_labels if entry[0] <= now]

        if not due:
            return

        self.pending_labels = [entry for entry in self.pending_labels if entry[0] > now]

        for reported_at, audit_id, label in due:
            AuditLog.objects.filter(id=audit_id).update(label=label, labeled_at=reported_at)

    def skip(self, reference, reason):
        self.skipped.append(dict(reference=reference, reason=reason))


def device_count(application):
    return DeviceIdentity.objects.filter(account_links__application=application).distinct().count()
