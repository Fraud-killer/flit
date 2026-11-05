"""
A rate-limit breach is a signal, the client address is the one the proxy saw,
and decisions have their own bucket.
"""

from unittest.mock import Mock, patch

import pytest
from django.test import RequestFactory


def middleware_with_limit_exceeded():
    from core.security.middleware import SecurityMiddleware
    from core.security.rate_limiter import RateLimitExceeded

    middleware = SecurityMiddleware(lambda request: Mock(status_code=200))
    patcher = patch.object(
        middleware, "_check_rate_limit",
        side_effect=RateLimitExceeded(limit=100, window=60, retry_after=7),
    )
    return middleware, patcher


class TestBreachIsRecorded:
    def test_a_breach_writes_a_security_event(self, application):
        from core.models import AuditLog

        middleware, patcher = middleware_with_limit_exceeded()
        request = RequestFactory().post(
            f"/api/v1/applications/{application.id}/audit-transaction",
            HTTP_AUTHORIZATION=f"HMAC-SHA256 {application.id}:deadbeef",
            HTTP_USER_AGENT="python-requests/2.31.0",
            REMOTE_ADDR="41.58.100.5",
        )

        with patcher:
            response = middleware(request)

        assert response.status_code == 429
        assert response["Retry-After"] == "7"

        log = AuditLog.objects.get(action="rate_limited")
        assert log.category == "security"
        assert log.ip_address == "41.58.100.5"
        assert log.user_agent == "python-requests/2.31.0"
        assert log.application_id == application.id
        assert log.context["limit"] == 100

    def test_an_unsigned_breach_is_still_recorded(self, db):
        from core.models import AuditLog

        middleware, patcher = middleware_with_limit_exceeded()
        request = RequestFactory().post("/api/v1/collect", REMOTE_ADDR="41.58.100.5")

        with patcher:
            middleware(request)

        log = AuditLog.objects.get(action="rate_limited")
        assert log.application_id is None

    def test_a_failing_record_does_not_change_the_response(self, db):
        middleware, patcher = middleware_with_limit_exceeded()
        request = RequestFactory().post("/api/v1/collect", REMOTE_ADDR="41.58.100.5")

        with patcher, patch("core.audit.logger.AuditLogger.log_security_event", side_effect=RuntimeError("db gone")):
            response = middleware(request)

        assert response.status_code == 429


class TestAuditBucket:
    def test_decisions_use_their_own_limit(self):
        from core.security.middleware import SecurityMiddleware
        from core.security.rate_limiter import RateLimiter

        from django.http import HttpResponse

        middleware = SecurityMiddleware(lambda request: HttpResponse())
        seen = []

        def check(identifier, action, config=None):
            seen.append(action)
            return dict(remaining=1, limit=1, reset=0)

        with patch.object(RateLimiter, "check", side_effect=check):
            middleware(RequestFactory().post("/api/v1/applications/abc/audit-transaction"))
            middleware(RequestFactory().get("/api/v1/applications/abc/decisions"))
            middleware(RequestFactory().post("/api/v1/collect"))

        assert seen == ["api_audit", "api_general", "device_collection"]


class TestTrustedProxyDepth:
    def request(self, forwarded, remote="10.0.0.9"):
        request = Mock()
        request.META = {"HTTP_X_FORWARDED_FOR": forwarded, "REMOTE_ADDR": remote, "HTTP_USER_AGENT": "x"}
        request.headers = {}
        return request

    def with_depth(self, depth):
        from core.security.rate_limiter import RateLimiter
        return patch.object(RateLimiter, "trusted_proxy_depth", return_value=depth)

    def test_legacy_reading_takes_the_first_entry(self):
        from core.security.rate_limiter import RateLimiter

        with self.with_depth(None):
            assert RateLimiter.client_ip(self.request("1.1.1.1, 2.2.2.2")) == "1.1.1.1"

    def test_depth_one_takes_the_entry_the_load_balancer_wrote(self):
        """The client wrote 1.1.1.1 itself; the balancer appended what it saw."""
        from core.security.rate_limiter import RateLimiter

        with self.with_depth(1):
            assert RateLimiter.client_ip(self.request("1.1.1.1, 2.2.2.2")) == "2.2.2.2"
            assert RateLimiter.client_ip(self.request("5.5.5.5")) == "5.5.5.5"

    def test_depth_two_for_two_proxies(self):
        from core.security.rate_limiter import RateLimiter

        with self.with_depth(2):
            assert RateLimiter.client_ip(self.request("1.1.1.1, 2.2.2.2, 3.3.3.3")) == "2.2.2.2"

    def test_depth_zero_ignores_the_header(self):
        from core.security.rate_limiter import RateLimiter

        with self.with_depth(0):
            assert RateLimiter.client_ip(self.request("1.1.1.1, 2.2.2.2", remote="9.9.9.9")) == "9.9.9.9"


class TestVelocityPace:
    def test_half_the_hourly_limit_in_five_minutes_is_a_warning(self, application, no_geoip):
        import asyncio
        from unittest.mock import AsyncMock
        from core.audit.auditor import Auditor
        from core.audit.events import TransactionEvent
        from tests.unit.test_session_scoring import write_event
        from core.audit.models import AuditLogCategory

        # 25 debits inside the last four minutes against a 50/hour limit.
        for index in range(25):
            write_event(
                application, ip_address="102.91.133.202", user_agent="Mozilla/5.0 Chrome/120.0",
                action="transaction_debit", actor_id="spender", seconds_ago=240 - index * 8,
                category=AuditLogCategory.TRANSACTION,
            )

        event = TransactionEvent(
            id="tx_pace", type="debit", amount=5, currency_code="USD", client_id="spender",
            ip_address="102.91.133.202", user_agent="Mozilla/5.0 Chrome/120.0",
        )
        with patch("core.services.fingerprint.FetchVisitData.async_call", AsyncMock(return_value=None)):
            result = asyncio.run(Auditor.audit(event, application.policy, send_alerts=False))

        assert "velocity_pace" in result.factors
        # Not yet over the hourly ceiling itself.
        assert "velocity_exceeded_per_hour" not in result.factors
