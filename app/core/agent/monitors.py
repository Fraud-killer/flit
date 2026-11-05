"""
"Wake me when": conditions over a subject, checked on a schedule.

A monitor is a row: a subject (an account, a device, an IP, or the whole
application), a metric, a threshold, a window, an expiry. `run_monitors`
evaluates every active one from the audit log and the streak counters; one
that fires alerts the team, tells the merchant's webhook, and may queue an
investigation under a playbook. A fired monitor stays fired: a person decides
whether to watch again.
"""

import logging
from datetime import timedelta

from django.utils import timezone

from core.models import (
    AuditLog, Case, CaseStatus, Monitor, MonitorStatus, MonitorMetric, MonitorAction, InvestigationTrigger,
)


logger = logging.getLogger(__name__)


class Monitors:
    @classmethod
    def measure(cls, monitor, *, now=None):
        """The metric's current value for the monitor's subject."""
        now = now or timezone.now()
        subject = monitor.subject or {}
        application_id = monitor.application_id
        fingerprint = cls.fingerprint(subject.get("device_id"))

        if monitor.metric == MonitorMetric.BLOCK_STREAK:
            from core.services.block_streak import BlockStreak
            origin = BlockStreak.origin_for(
                device_fingerprint=fingerprint, ip_address=subject.get("ip_address"),
                client_id=subject.get("client_id"),
            )
            return BlockStreak.read(application_id, origin)["consecutive"] if origin else 0

        if monitor.metric == MonitorMetric.OPEN_CASES:
            cases = Case.objects.filter(application_id=application_id, status=CaseStatus.OPEN)
            if subject.get("client_id"):
                cases = cases.filter(audit_log__actor_id=subject["client_id"])
            return cases.count()

        since = now - timedelta(minutes=monitor.window_minutes)
        logs = AuditLog.objects.filter(application_id=application_id, timestamp__gte=since)
        if subject.get("client_id"):
            logs = logs.filter(actor_id=subject["client_id"])
        if fingerprint:
            logs = logs.filter(device_fingerprint=fingerprint)
        if subject.get("ip_address"):
            logs = logs.filter(ip_address=subject["ip_address"])

        if monitor.metric == MonitorMetric.DECISIONS:
            return logs.count()
        if monitor.metric == MonitorMetric.BLOCKS:
            return logs.filter(context__should_block=True).count()
        if monitor.metric == MonitorMetric.FACTOR:
            return sum(1 for factors in logs.values_list("risk_factors", flat=True)[:5000] if monitor.factor in (factors or []))
        return 0

    @staticmethod
    def fingerprint(device_id):
        """
        The audit log stores the device's external fingerprint; every read
        tool hands the agent the DeviceIdentity id. Translate, so a monitor
        the agent opened watches the device it meant.
        """
        if not device_id:
            return None
        from devkit.checks import is_uuid_str
        if is_uuid_str(str(device_id)):
            from core.models import DeviceIdentity
            external = DeviceIdentity.objects.filter(id=device_id).values_list("external_id", flat=True).first()
            return external or device_id
        return device_id

    @classmethod
    def evaluate(cls, *, application=None, now=None):
        """Check every active monitor. Returns (fired, expired) lists."""
        now = now or timezone.now()
        queryset = Monitor.objects.filter(status=MonitorStatus.ACTIVE).select_related("application")
        if application is not None:
            queryset = queryset.filter(application=application)

        fired, expired = [], []
        for monitor in queryset:
            if monitor.expires_at <= now:
                monitor.status = MonitorStatus.EXPIRED
                monitor.save(update_fields=["status"])
                expired.append(monitor)
                continue
            try:
                value = cls.measure(monitor, now=now)
            except Exception:
                logger.exception("Could not measure monitor %s", monitor.id)
                continue
            if value >= monitor.threshold:
                cls.fire(monitor, value, now=now)
                fired.append(monitor)
        return fired, expired

    @classmethod
    def fire(cls, monitor, value, *, now=None):
        from core.outbound import Webhooks
        from core.realtime.alerts import Alert, AlertCategory, AlertLevel, AlertManager

        now = now or timezone.now()
        monitor.status = MonitorStatus.FIRED
        monitor.fired_at = now
        monitor.fired_value = value
        investigation = None

        if monitor.action == MonitorAction.INVESTIGATE and monitor.playbook:
            try:
                from .loop import Investigations
                investigation = Investigations.open(
                    application=monitor.application, playbook=monitor.playbook, subject=dict(monitor.subject or {}, monitor=monitor.name),
                    trigger=InvestigationTrigger.MONITOR,
                )
                monitor.investigation = investigation
            except Exception:
                logger.exception("Could not open investigation for monitor %s", monitor.id)
        monitor.save()

        payload = dict(
            monitor_id=str(monitor.id), name=monitor.name, metric=monitor.metric, factor=monitor.factor or None,
            threshold=monitor.threshold, value=value, subject=monitor.subject, window_minutes=monitor.window_minutes,
            investigation_id=str(investigation.id) if investigation else None,
        )
        Webhooks.enqueue(monitor.application, "monitor.fired", payload)
        try:
            AlertManager.send_alert_sync(Alert(
                level=AlertLevel.WARNING, category=AlertCategory.SECURITY, title=f"Monitor fired: {monitor.name}",
                message=f"{monitor.metric} reached {value} (threshold {monitor.threshold})",
                application_id=str(monitor.application_id), organization_id=str(monitor.application.organization_id),
                resource_type="monitor", resource_id=str(monitor.id), context=payload,
            ))
        except Exception:
            logger.warning("Could not send monitor alert", exc_info=True)
        return monitor
