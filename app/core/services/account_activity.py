"""
What an account has been doing lately, read back from recorded decisions.

Mule accounts are recognised by the shape of their money movement rather
than by any single transaction: funds arrive from many places and leave
almost immediately, or an account sleeps for months and then wakes up moving
money. Those shapes need history, which the audit log now keeps.
"""

from datetime import timedelta
from django.utils import timezone

from core.models import AuditLog
from core.audit.models import AuditLogCategory


CREDIT = "credit"
DEBIT = "debit"


class AccountActivity:
    """A window of an account's recorded transactions, summarised."""

    LOOKBACK_DAYS = 180
    MAX_EVENTS = 1000

    def __init__(self, *, events, now=None):
        self.events = events
        self.now = now or timezone.now()

    @classmethod
    def load(cls, *, application, client_id, exclude_audit_id=None):
        queryset = (
            AuditLog.objects
            .filter(
                application_id=application.id,
                actor_id=client_id,
                category=AuditLogCategory.TRANSACTION,
                timestamp__gte=timezone.now() - timedelta(days=cls.LOOKBACK_DAYS),
            )
            .order_by("-timestamp")
        )

        if exclude_audit_id:
            queryset = queryset.exclude(id=exclude_audit_id)

        events = [
            cls.summarize(log)
            for log in queryset[:cls.MAX_EVENTS]
        ]

        return cls(events=events)

    @staticmethod
    def summarize(log):
        context = log.context or {}
        amount = context.get("amount")

        return dict(
            timestamp=log.timestamp,
            type=context.get("transaction_type"),
            amount=float(amount) if isinstance(amount, (int, float)) else None,
            currency_code=context.get("currency_code"),
            counterparty_id=context.get("counterparty_id"),
            device_id=context.get("device_id"),
            label=log.label,
        )

    def within(self, minutes=None, days=None, kind=None):
        since = self.now - timedelta(minutes=minutes or 0, days=days or 0)

        return [
            event for event in self.events
            if event["timestamp"] >= since and (kind is None or event["type"] == kind)
        ]

    def total(self, events):
        return sum(event["amount"] or 0 for event in events)

    def counterparties(self, events):
        return {event["counterparty_id"] for event in events if event["counterparty_id"]}

    @property
    def last_activity_at(self):
        return self.events[0]["timestamp"] if self.events else None

    def dormant_days(self):
        """Days of silence before now, or None for an account with no history."""
        if not self.last_activity_at:
            return None

        return (self.now - self.last_activity_at).total_seconds() / 86400

    def credits_since_last_debit(self):
        """Credits that arrived after the account last paid anything out."""
        credits = []

        for event in self.events:  # newest first
            if event["type"] == DEBIT:
                break
            if event["type"] == CREDIT:
                credits.append(event)

        return credits
