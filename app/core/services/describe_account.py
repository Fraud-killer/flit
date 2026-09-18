from django.db.models import Count

from core.models import AuditLog, Case, DeviceAccountLink
from core.services.account_activity import AccountActivity


MULE_CODES = [
    "pass_through_funds",
    "many_unique_payers",
    "credit_structuring",
    "dormant_account_activity",
    "account_farming",
    "mule_network_device",
    "multi_accounting",
]


class DescribeAccount:
    """
    An account's mule profile: how money moves through it, which devices it
    shares, and what FLIT has flagged. This is the lookup a fraud team runs
    when a payment is held.
    """

    MAX_DEVICES = 25

    @classmethod
    def call(cls, *, application, client_id):
        activity = AccountActivity.load(application=application, client_id=client_id)

        logs = AuditLog.objects.filter(
            application_id=application.id,
            actor_id=client_id,
        )

        credits = activity.within(days=30, kind="credit")
        debits = activity.within(days=30, kind="debit")

        links = (
            DeviceAccountLink.objects
            .filter(application=application, client_id=client_id)
            .select_related("device")
            .order_by("-last_seen_at")[:cls.MAX_DEVICES]
        )

        return dict(
            client_id=client_id,
            first_seen_at=activity.events[-1]["timestamp"] if activity.events else None,
            last_seen_at=activity.last_activity_at,
            dormant_days=round(activity.dormant_days(), 1) if activity.dormant_days() else None,
            flow_30d=dict(
                credits=len(credits),
                debits=len(debits),
                credited=activity.total(credits),
                debited=activity.total(debits),
                unique_payers=len(activity.counterparties(credits)),
                unique_payees=len(activity.counterparties(debits)),
                # Close to 1 means money leaves as fast as it arrives.
                pass_through_ratio=cls.ratio(activity.total(debits), activity.total(credits)),
            ),
            devices=[
                dict(
                    device_id=str(link.device_id),
                    source=link.device.source,
                    flags=link.device.flags,
                    event_count=link.event_count,
                    first_seen_at=link.first_seen_at,
                    last_seen_at=link.last_seen_at,
                    shared_with_accounts=link.device.account_links.filter(
                        application=application,
                    ).exclude(client_id=client_id).count(),
                )
                for link in links
            ],
            mule_signals=cls.mule_signals(logs),
            labels=dict(logs.exclude(label=None).values_list("label").annotate(count=Count("id"))),
            open_cases=Case.objects.filter(
                application=application,
                audit_log__actor_id=client_id,
                status="open",
            ).count(),
            decisions=logs.count(),
        )

    @classmethod
    def mule_signals(cls, logs):
        """How often each mule-related factor has fired for this account."""
        counts = {}

        for factors in logs.values_list("risk_factors", flat=True):
            for code in factors or []:
                if code in MULE_CODES:
                    counts[code] = counts.get(code, 0) + 1

        return counts

    @staticmethod
    def ratio(numerator, denominator):
        return round(numerator / denominator, 4) if denominator else None
