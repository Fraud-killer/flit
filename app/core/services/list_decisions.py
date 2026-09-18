from datetime import timedelta
from django.db import connection
from django.db.models import Count
from django.utils import timezone

from core.models import AuditLog, DeviceIdentity


class ListDecisions:
    """The decision feed behind the console: what FLIT decided, and why."""

    @classmethod
    def call(cls, *, application, filters):
        queryset = cls.queryset(application, filters)
        total = queryset.count()

        decisions = queryset[filters.offset:filters.offset + filters.limit]

        return dict(
            total=total,
            limit=filters.limit,
            offset=filters.offset,
            summary=cls.summary(application, filters),
            decisions=[cls.serialize(decision) for decision in decisions],
        )

    @classmethod
    def queryset(cls, application, filters):
        since = timezone.now() - timedelta(days=filters.days)

        queryset = (
            AuditLog.objects
            .filter(application_id=application.id, timestamp__gte=since)
            .select_related("case")
        )

        if filters.level:
            queryset = queryset.filter(context__risk_level=filters.level)

        if filters.label:
            queryset = queryset.filter(label=filters.label)

        if filters.unlabelled:
            queryset = queryset.filter(label=None)

        if filters.factor:
            queryset = cls.filter_by_factor(queryset, filters.factor)

        if filters.client_id:
            queryset = queryset.filter(actor_id=filters.client_id)

        if filters.device_id:
            fingerprint = (
                DeviceIdentity.objects
                .filter(id=filters.device_id, account_links__application=application)
                .values_list("external_id", flat=True)
                .first()
            )
            queryset = queryset.filter(device_fingerprint=fingerprint or "")

        return queryset.order_by("-timestamp")

    @classmethod
    def filter_by_factor(cls, queryset, factor):
        """
        JSON containment is a Postgres feature; SQLite (used in development
        and tests) needs the membership test done in Python.
        """
        if connection.features.supports_json_field_contains:
            return queryset.filter(risk_factors__contains=[factor])

        matching = [
            pk for pk, factors in queryset.values_list("id", "risk_factors")
            if factor in (factors or [])
        ]

        return queryset.filter(id__in=matching)

    @classmethod
    def summary(cls, application, filters):
        queryset = cls.queryset(application, filters)

        return dict(
            by_label=dict(
                queryset.exclude(label=None).values_list("label").annotate(count=Count("id"))
            ),
            open_cases=queryset.filter(case__status="open").count(),
        )

    @classmethod
    def serialize(cls, decision):
        context = decision.context or {}
        case = getattr(decision, "case", None)

        return dict(
            audit_id=str(decision.id),
            timestamp=decision.timestamp,
            action=decision.action,
            category=decision.category,
            event_id=decision.resource_id,
            client_id=decision.actor_id,
            device_id=context.get("device_id"),
            ip_address=decision.ip_address,
            risk_score=decision.risk_score,
            risk_level=context.get("risk_level"),
            should_block=context.get("should_block"),
            factors=decision.risk_factors,
            outcome=decision.outcome,
            label=decision.label,
            labeled_at=decision.labeled_at,
            case=None if case is None else dict(id=str(case.id), status=case.status),
        )
