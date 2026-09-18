"""
Tests for FLIT's own device identification: signal normalisation, the
consistency checks, device matching and the public /v1/collect endpoint.
"""

import asyncio
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta


def chrome_signals(**overrides):
    """A plausible desktop Chrome on macOS in London."""
    offset = -int(datetime.now(ZoneInfo("Europe/London")).utcoffset().total_seconds() // 60)

    signals = dict(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0",
        ua_brands=["Chromium/120"],
        ua_platform="macOS",
        platform="MacIntel",
        languages=["en-GB", "en"],
        timezone="Europe/London",
        timezone_offset=offset,
        screen=dict(width=1728, height=1117, color_depth=30, pixel_ratio=2),
        hardware_concurrency=8,
        device_memory=16,
        touch_points=0,
        plugins=["PDF Viewer"],
        webdriver=False,
        canvas="c" * 32,
        webgl="w" * 32,
        webgl_renderer="Apple M2",
        audio="a" * 32,
        fonts="f" * 32,
    )
    signals.update(overrides)
    return signals


class TestSignalNormalisation:
    def test_platform_family_from_any_available_field(self):
        from core.intelligence.device_signals import platform_family

        assert platform_family(dict(platform="MacIntel")) == "macos"
        assert platform_family(dict(user_agent="... (iPhone; CPU iPhone OS 17_0)")) == "ios"
        assert platform_family(dict(ua_platform="Windows")) == "windows"
        assert platform_family(dict()) == "unknown"

    def test_signature_ignores_volatile_components(self):
        from core.intelligence.device_signals import normalize, signature_hash

        stable = signature_hash(normalize(chrome_signals()))
        moved = signature_hash(normalize(chrome_signals(timezone="Europe/Paris", languages=["fr-FR"])))
        rebuilt = signature_hash(normalize(chrome_signals(canvas="z" * 32)))

        # Travelling does not change the signature; a new canvas does.
        assert stable == moved
        assert stable != rebuilt

    def test_similarity_scores_shared_components(self):
        from core.intelligence.device_signals import normalize, similarity

        base = normalize(chrome_signals())

        assert similarity(base, base) == 1.0
        assert 0.8 < similarity(base, normalize(chrome_signals(canvas="z" * 32))) < 1.0
        assert similarity(base, normalize(dict())) < 0.3


class TestConsistencyChecks:
    def flags(self, **overrides):
        from core.intelligence.device_signals import consistency_flags

        ip_country_code = overrides.pop("ip_country_code", None)
        return consistency_flags(chrome_signals(**overrides), ip_country_code=ip_country_code)

    def test_a_consistent_browser_raises_nothing(self):
        assert self.flags(ip_country_code="GB") == []

    def test_detects_a_spoofed_timezone(self):
        assert "spoofed_timezone" in self.flags(timezone_offset=-480)
        assert "spoofed_timezone" in self.flags(timezone="Not/AZone")

    def test_detects_contradictory_platforms(self):
        assert "platform_mismatch" in self.flags(ua_platform="Windows")
        assert "platform_mismatch" not in self.flags()

    def test_detects_software_rendering(self):
        assert "software_renderer" in self.flags(webgl_renderer="Google SwiftShader")
        assert "software_renderer" in self.flags(webgl_renderer="Mesa OffScreen (llvmpipe)")

    def test_detects_automation_markers(self):
        assert "automation_markers" in self.flags(webdriver=True)
        assert "automation_markers" in self.flags(languages=[], plugins=[])
        assert "automation_markers" in self.flags(hardware_concurrency=0)

    def test_detects_a_phone_that_cannot_be_touched(self):
        mobile = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"

        assert "device_class_mismatch" in self.flags(
            user_agent=mobile, platform="iPhone", ua_platform="iOS", touch_points=0,
        )
        assert "device_class_mismatch" in self.flags(touch_points=5)

    def test_locale_country_mismatch_is_only_raised_with_an_ip_country(self):
        assert "locale_country_mismatch" in self.flags(ip_country_code="RU")
        assert "locale_country_mismatch" not in self.flags(ip_country_code="GB")
        assert "locale_country_mismatch" not in self.flags()


class TestIdentifyDevice:
    def identify(self, application, signals=None, device_key=None):
        from core.services.identify_device import IdentifyDevice

        return IdentifyDevice.call(
            application=application,
            signals=signals or chrome_signals(),
            device_key=device_key,
        )

    def test_recognises_the_same_device(self, application):
        first, first_match = self.identify(application)
        second, second_match = self.identify(application)

        assert first_match == "new"
        assert second_match == "signature"
        assert first.id == second.id
        assert first.source == "flit"
        assert first.external_id.startswith("flit_dk_")

    def test_recognises_a_device_after_a_small_change(self, application):
        first, _ = self.identify(application)
        # A browser update changes the canvas digest but little else.
        second, matched_by = self.identify(application, chrome_signals(canvas="z" * 32))

        assert second.id == first.id
        assert matched_by == "similarity"

    def test_treats_a_different_device_as_new(self, application):
        first, _ = self.identify(application)
        second, matched_by = self.identify(application, chrome_signals(
            canvas="z" * 32, webgl="y" * 32, audio="x" * 32, fonts="v" * 32,
            webgl_renderer="Intel Iris", screen=dict(width=1920, height=1080, color_depth=24, pixel_ratio=1),
            hardware_concurrency=4, device_memory=8,
        ))

        assert second.id != first.id
        assert matched_by == "new"

    def test_a_returned_device_key_survives_heavy_drift(self, application):
        first, _ = self.identify(application)

        drifted = chrome_signals(
            canvas="z" * 32, webgl="y" * 32, audio="x" * 32,
            screen=dict(width=1920, height=1080, color_depth=24, pixel_ratio=1),
        )
        second, matched_by = self.identify(application, drifted, device_key=first.external_id)

        assert second.id == first.id
        assert matched_by == "device_key"

    def test_an_unrelated_device_key_is_not_trusted(self, application):
        first, _ = self.identify(application)

        unrelated = chrome_signals(
            canvas="z" * 32, webgl="y" * 32, audio="x" * 32, fonts="v" * 32,
            webgl_renderer="Intel Iris", user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0",
            platform="Win32", ua_platform="Windows",
            screen=dict(width=1920, height=1080, color_depth=24, pixel_ratio=1),
            hardware_concurrency=4, device_memory=8,
        )
        second, matched_by = self.identify(application, unrelated, device_key=first.external_id)

        # A copied key cannot make one device pass as another.
        assert second.id != first.id
        assert matched_by == "new"

    def test_devices_are_not_shared_between_applications(self, application, second_application):
        first, _ = self.identify(application)
        second, matched_by = self.identify(second_application)

        # Cross-merchant linking is opt-in and not built yet.
        assert second.id != first.id
        assert matched_by == "new"

    def test_stale_candidates_are_not_compared(self, application):
        from core.models import DeviceSignature
        from django.utils import timezone as django_timezone

        first, _ = self.identify(application)

        DeviceSignature.objects.all().update(
            last_seen_at=django_timezone.now() - timedelta(days=120),
            signature_hash="stale",
        )

        second, matched_by = self.identify(application, chrome_signals(canvas="z" * 32))

        assert second.id != first.id
        assert matched_by == "new"


class TestCollectEndpoint:
    def post(self, client, body):
        return client.post("/api/v1/collect", body, format="json")

    def client(self):
        from rest_framework.test import APIClient
        return APIClient()

    def test_collects_signals_without_authentication(self, application):
        from core.models import DeviceIdentity

        response = self.post(self.client(), dict(key=application.collect_key, signals=chrome_signals()))

        assert response.status_code == 200, response.data
        data = response.data["data"]
        assert data["visit_token"]
        assert data["device_key"].startswith("flit_dk_")
        assert data["expires_in"] == 1800
        assert response["Access-Control-Allow-Origin"] == "*"

        device = DeviceIdentity.objects.get(external_id=data["device_key"])
        assert device.source == "flit"

    def test_returns_the_same_device_key_for_the_same_browser(self, application):
        client = self.client()
        body = dict(key=application.collect_key, signals=chrome_signals())

        first = self.post(client, body).data["data"]["device_key"]
        body["device_key"] = first
        second = self.post(client, body).data["data"]["device_key"]

        assert first == second

    def test_rejects_an_unknown_collection_key(self, application):
        response = self.post(self.client(), dict(key="flit_pk_nope", signals=chrome_signals()))

        assert response.status_code == 400
        assert [error["code"] for error in response.data["errors"]] == ["collect_key_exist"]

    def test_rejects_a_missing_or_malformed_payload(self, application):
        response = self.post(self.client(), dict(key=application.collect_key))
        assert [error["code"] for error in response.data["errors"]] == ["required"]

        response = self.post(self.client(), dict(key=application.collect_key, signals="nope"))
        assert [error["code"] for error in response.data["errors"]] == ["dict"]

    def test_preflight_is_allowed(self, application):
        response = self.client().options("/api/v1/collect")

        assert response.status_code == 200
        assert response["Access-Control-Allow-Methods"] == "POST, OPTIONS"

    def test_stores_no_raw_signals(self, application):
        from core.models import DeviceSignature

        self.post(self.client(), dict(key=application.collect_key, signals=chrome_signals()))
        stored = str(DeviceSignature.objects.get().components)

        assert "Mozilla" not in stored
        assert "c" * 32 not in stored


class TestAuditWithCollectedVisit:
    def collect(self, application, signals=None, device_key=None, ip_address="81.2.69.160"):
        from core.services.collect_visit import CollectVisit

        visit_token, identity, _ = CollectVisit.call(
            application=application,
            signals=signals or chrome_signals(),
            device_key=device_key,
            ip_address=ip_address,
        )
        return visit_token, identity

    def audit(self, application, visit_token, client_id="user_1", event_id="tx_1"):
        from core.audit.auditor import Auditor
        from core.audit.events import TransactionEvent

        event = TransactionEvent(
            id=event_id, type="debit", amount=25, currency_code="NGN",
            client_id=client_id, visit_token=visit_token,
        )

        return asyncio.run(Auditor.audit(event, application.policy, send_alerts=False))

    def test_a_collected_visit_identifies_the_device(self, application, no_geoip):
        visit_token, identity = self.collect(application)

        result = self.audit(application, visit_token)

        assert result.device_id == str(identity.id)

    def test_consistency_flags_become_risk_factors(self, application, no_geoip):
        visit_token, _ = self.collect(application, chrome_signals(
            webdriver=True, webgl_renderer="Google SwiftShader", timezone_offset=-480,
        ))

        result = self.audit(application, visit_token)

        assert "automation_markers" in result.factors
        assert "software_renderer" in result.factors
        assert "spoofed_timezone" in result.factors
        assert result.risk_level in ("high", "critical")

    def test_a_clean_collected_visit_stays_low_risk(self, application, no_geoip):
        visit_token, _ = self.collect(application)

        result = self.audit(application, visit_token)

        assert result.risk_level == "low"
        assert not [code for code in result.factors if code.startswith(("spoofed", "automation"))]

    def test_multi_accounting_works_with_flit_devices(self, application, no_geoip):
        visit_token, _ = self.collect(application)
        result = None

        for index in range(1, 5):
            result = self.audit(application, visit_token, client_id=f"user_{index}", event_id=f"tx_{index}")

        assert "multi_accounting" in result.factors

    def test_an_unknown_visit_token_is_harmless(self, application, no_geoip):
        result = self.audit(application, "vt_does_not_exist")

        assert result.device_id is None
        assert result.risk_level == "low"

    def test_an_expired_visit_token_is_harmless(self, application, no_geoip):
        from django.core.cache import cache
        from core.services.collect_visit import CollectVisit

        visit_token, _ = self.collect(application)
        cache.delete(CollectVisit.cache_key(visit_token))

        result = self.audit(application, visit_token)

        assert result.device_id is None
