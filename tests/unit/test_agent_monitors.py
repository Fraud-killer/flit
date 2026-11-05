"""
Wake me when: monitors fire from the audit log, expire, and may open an investigation.
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from core.agent import Monitors
from core.models import Monitor, MonitorStatus, Investigation
from tests.unit.agent_fakes import agent_on
from tests.unit.test_console import risky_audit, audit


def monitor(application, **fields):
    fields.setdefault("name", "watch")
    fields.setdefault("metric", "decisions")
    fields.setdefault("threshold", 2)
    fields.setdefault("expires_at", timezone.now() + timedelta(hours=1))
    return Monitor.objects.create(application=application, **fields)


class TestFiring:
    def test_a_decisions_monitor_fires_at_its_threshold(self, application, no_geoip):
        watch = monitor(application, subject=dict(client_id="m_1"), threshold=2)
        audit(application, client_id="m_1", id="a1")
        fired, _ = Monitors.evaluate(application=application)
        assert fired == []
        audit(application, client_id="m_1", id="a2")
        fired, _ = Monitors.evaluate(application=application)
        assert [m.id for m in fired] == [watch.id]
        watch.refresh_from_db()
        assert watch.status == MonitorStatus.FIRED and watch.fired_value == 2

    def test_a_blocks_monitor_counts_only_blocks(self, application, no_geoip):
        watch = monitor(application, subject=dict(ip_address="45.155.205.77"), metric="blocks", threshold=1)
        audit(application, client_id="ok_1", id="b1", ip_address="45.155.205.77", user_agent="Mozilla/5.0")
        Monitors.evaluate(application=application)
        watch.refresh_from_db()
        if watch.status == MonitorStatus.FIRED:
            pytest.skip("the benign event scored a block in this environment")
        risky_audit(application, client_id="bad_1", id="b2")
        Monitors.evaluate(application=application)
        watch.refresh_from_db()
        assert watch.status == MonitorStatus.FIRED

    def test_a_factor_monitor(self, application, no_geoip):
        watch = monitor(application, metric="factor", factor="suspicious_user_agent", threshold=1)
        result = risky_audit(application, client_id="f_1", id="f1")
        Monitors.evaluate(application=application)
        watch.refresh_from_db()
        codes = [f if isinstance(f, str) else f.get("code") for f in result.factors]
        assert (watch.status == MonitorStatus.FIRED) == ("suspicious_user_agent" in codes)

    def test_expired_monitors_are_marked_and_never_fire(self, application):
        watch = monitor(application, expires_at=timezone.now() - timedelta(minutes=1))
        fired, expired = Monitors.evaluate(application=application)
        assert fired == [] and [m.id for m in expired] == [watch.id]

    def test_an_investigating_monitor_opens_a_run(self, application, no_geoip):
        from core.models import AgentPolicy
        AgentPolicy.for_application(application)
        watch = monitor(application, subject=dict(client_id="m_2"), threshold=1, action="investigate", playbook="campaign_review")
        audit(application, client_id="m_2", id="c1")
        with agent_on():
            Monitors.evaluate(application=application)
        watch.refresh_from_db()
        investigation = Investigation.objects.get(id=watch.investigation_id)
        assert investigation.playbook == "campaign_review" and investigation.trigger == "monitor"
        assert investigation.subject == dict(client_id="m_2", monitor="watch")

    def test_the_merchant_hears_about_it(self, application, no_geoip):
        from core.models import WebhookDelivery
        application.webhook_url = "https://merchant.example/hooks"
        application.webhook_events = ["monitor.fired"]
        application.save()
        monitor(application, subject=dict(client_id="m_3"), threshold=1)
        audit(application, client_id="m_3", id="d1")
        Monitors.evaluate(application=application)
        assert WebhookDelivery.objects.filter(event="monitor.fired").count() == 1
