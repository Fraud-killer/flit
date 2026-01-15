"""
Unit tests for FLIT security components.

Usage:
    pytest tests/unit/test_security.py -v
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from django.test import RequestFactory


class TestRateLimiter:
    """Tests for the rate limiter."""

    def test_rate_limiter_allows_requests_under_limit(self):
        from core.security.rate_limiter import RateLimiter, RateLimitConfig

        with patch("core.security.rate_limiter.cache") as mock_cache:
            mock_cache.get.return_value = []

            config = RateLimitConfig(requests=10, window_seconds=60)
            result = RateLimiter.check("test_user", "api_general", config)

            assert result["remaining"] == 9
            assert result["limit"] == 10

    def test_rate_limiter_blocks_when_limit_exceeded(self):
        from core.security.rate_limiter import RateLimiter, RateLimitConfig, RateLimitExceeded

        with patch("core.security.rate_limiter.cache") as mock_cache:
            mock_cache.get.side_effect = [
                None,
                [time.time() - i for i in range(10)],
            ]

            config = RateLimitConfig(requests=10, window_seconds=60)

            with pytest.raises(RateLimitExceeded) as exc_info:
                RateLimiter.check("test_user", "api_general", config)

            assert exc_info.value.limit == 10
            assert exc_info.value.retry_after > 0

    def test_rate_limiter_blocks_with_duration(self):
        from core.security.rate_limiter import RateLimiter, RateLimitConfig, RateLimitExceeded

        with patch("core.security.rate_limiter.cache") as mock_cache:
            mock_cache.get.side_effect = [
                None,
                [time.time() - i for i in range(5)],
            ]

            config = RateLimitConfig(
                requests=5,
                window_seconds=60,
                block_duration_seconds=300,
            )

            with pytest.raises(RateLimitExceeded) as exc_info:
                RateLimiter.check("test_user", "authentication", config)

            assert exc_info.value.retry_after == 300

    def test_get_client_identifier_with_ip(self):
        from core.security.rate_limiter import RateLimiter

        request = Mock()
        request.META = {
            "REMOTE_ADDR": "192.168.1.1",
            "HTTP_USER_AGENT": "Mozilla/5.0",
        }
        request.headers = {}

        identifier = RateLimiter.get_client_identifier(request)
        assert "192.168.1.1" in identifier

    def test_get_client_identifier_with_forwarded_ip(self):
        from core.security.rate_limiter import RateLimiter

        request = Mock()
        request.META = {
            "HTTP_X_FORWARDED_FOR": "10.0.0.1, 192.168.1.1",
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_USER_AGENT": "Mozilla/5.0",
        }
        request.headers = {}

        identifier = RateLimiter.get_client_identifier(request)
        assert "10.0.0.1" in identifier


class TestReplayProtection:
    """Tests for replay attack protection."""

    def test_validates_valid_timestamp(self):
        from core.security.replay_protection import ReplayProtection

        current_time = str(int(time.time()))
        result = ReplayProtection.validate_timestamp(current_time)
        assert result == int(current_time)

    def test_rejects_missing_timestamp(self):
        from core.security.replay_protection import ReplayProtection, ReplayAttackDetected

        with pytest.raises(ReplayAttackDetected) as exc_info:
            ReplayProtection.validate_timestamp(None)

        assert "Missing timestamp" in str(exc_info.value)

    def test_rejects_old_timestamp(self):
        from core.security.replay_protection import ReplayProtection, ReplayAttackDetected

        old_time = str(int(time.time()) - 120)

        with pytest.raises(ReplayAttackDetected) as exc_info:
            ReplayProtection.validate_timestamp(old_time)

        assert "outside tolerance" in str(exc_info.value)

    def test_rejects_future_timestamp(self):
        from core.security.replay_protection import ReplayProtection, ReplayAttackDetected

        future_time = str(int(time.time()) + 120)

        with pytest.raises(ReplayAttackDetected) as exc_info:
            ReplayProtection.validate_timestamp(future_time)

        assert "outside tolerance" in str(exc_info.value)

    def test_validates_nonce(self):
        from core.security.replay_protection import ReplayProtection

        with patch("core.security.replay_protection.cache") as mock_cache:
            mock_cache.get.return_value = None

            nonce = "a" * 32
            ReplayProtection.validate_nonce(nonce, "app_123")

            mock_cache.set.assert_called_once()

    def test_rejects_reused_nonce(self):
        from core.security.replay_protection import ReplayProtection, ReplayAttackDetected

        with patch("core.security.replay_protection.cache") as mock_cache:
            mock_cache.get.return_value = True

            with pytest.raises(ReplayAttackDetected) as exc_info:
                ReplayProtection.validate_nonce("a" * 32, "app_123")

            assert "already used" in str(exc_info.value)

    def test_rejects_short_nonce(self):
        from core.security.replay_protection import ReplayProtection, ReplayAttackDetected

        with pytest.raises(ReplayAttackDetected) as exc_info:
            ReplayProtection.validate_nonce("short", "app_123")

        assert "Invalid nonce length" in str(exc_info.value)


class TestRequestValidator:
    """Tests for request validation."""

    def test_sanitizes_string(self):
        from core.security.request_validator import RequestValidator

        result = RequestValidator.sanitize_string("  hello world  ")
        assert result == "hello world"

    def test_truncates_long_string(self):
        from core.security.request_validator import RequestValidator

        long_string = "a" * 2000
        result = RequestValidator.sanitize_string(long_string, max_length=100)
        assert len(result) == 100

    def test_detects_xss(self):
        from core.security.request_validator import RequestValidator

        dangerous = "<script>alert('xss')</script>"
        result = RequestValidator.check_dangerous_content(dangerous)
        assert result is not None

    def test_detects_sql_injection(self):
        from core.security.request_validator import RequestValidator

        dangerous = "'; DROP TABLE users; --"
        result = RequestValidator.check_dangerous_content(dangerous)
        assert result is not None

    def test_validates_uuid(self):
        from core.security.request_validator import RequestValidator

        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        result = RequestValidator.validate_uuid(valid_uuid, "id")
        assert result is None

        invalid_uuid = "not-a-uuid"
        result = RequestValidator.validate_uuid(invalid_uuid, "id")
        assert result is not None
        assert result.code == "invalid_uuid"

    def test_validates_email(self):
        from core.security.request_validator import RequestValidator

        valid_email = "test@example.com"
        result = RequestValidator.validate_email(valid_email, "email")
        assert result is None

        invalid_email = "not-an-email"
        result = RequestValidator.validate_email(invalid_email, "email")
        assert result is not None

    def test_validates_request_body(self):
        from core.security.request_validator import RequestValidator

        data = {
            "name": "John Doe",
            "amount": 100.50,
        }

        result = RequestValidator.validate_request_body(
            data,
            required_fields=["name", "amount"],
        )

        assert result.valid
        assert "name" in result.sanitized_data

    def test_detects_missing_required_fields(self):
        from core.security.request_validator import RequestValidator

        data = {"name": "John"}

        result = RequestValidator.validate_request_body(
            data,
            required_fields=["name", "email"],
        )

        assert not result.valid
        assert any(e.field == "email" for e in result.errors)


class TestIPIntelligence:
    """Tests for IP intelligence."""

    def test_detects_private_ip(self):
        from core.intelligence.ip_intelligence import IPIntelligence

        assert IPIntelligence._is_private_ip("192.168.1.1")
        assert IPIntelligence._is_private_ip("10.0.0.1")
        assert IPIntelligence._is_private_ip("127.0.0.1")
        assert not IPIntelligence._is_private_ip("8.8.8.8")

    def test_is_suspicious(self):
        from core.intelligence.ip_intelligence import IPIntelligence, IPRiskInfo

        high_risk = IPRiskInfo(
            ip_address="1.2.3.4",
            is_tor=True,
            risk_score=0.8,
        )
        assert IPIntelligence.is_suspicious(high_risk)

        low_risk = IPRiskInfo(
            ip_address="8.8.8.8",
            risk_score=0.1,
        )
        assert not IPIntelligence.is_suspicious(low_risk)


class TestBotDetection:
    """Tests for bot detection."""

    def test_detects_known_bot_user_agent(self):
        from core.intelligence.bot_detection import BotDetector

        result = BotDetector.detect("Googlebot/2.1")
        assert result.is_bot
        assert result.bot_type == "search_crawler"

    def test_detects_curl(self):
        from core.intelligence.bot_detection import BotDetector

        result = BotDetector.detect("curl/7.68.0")
        assert result.is_bot
        assert result.bot_type == "http_client"

    def test_detects_headless_chrome(self):
        from core.intelligence.bot_detection import BotDetector

        result = BotDetector.detect("Mozilla/5.0 HeadlessChrome/91.0")
        assert result.is_bot or result.confidence >= 0.7
        assert "headless_indicator" in str(result.signals)

    def test_detects_missing_user_agent(self):
        from core.intelligence.bot_detection import BotDetector

        result = BotDetector.detect(None)
        assert "missing_user_agent" in result.signals
        assert result.confidence >= 0.4

    def test_allows_legitimate_browser(self):
        from core.intelligence.bot_detection import BotDetector

        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36"
        result = BotDetector.detect(ua)
        assert not result.is_bot

    def test_is_allowed_bot(self):
        from core.intelligence.bot_detection import BotDetector, BotDetectionResult

        search_bot = BotDetectionResult(is_bot=True, bot_type="search_crawler")
        assert BotDetector.is_allowed_bot(search_bot)

        scraper = BotDetectionResult(is_bot=True, bot_type="scraper")
        assert not BotDetector.is_allowed_bot(scraper)


class TestRiskScoring:
    """Tests for risk scoring engine."""

    def test_calculates_risk_score(self):
        from core.scoring.risk_engine import RiskEngine, RiskLevel

        engine = RiskEngine()

        messages = [
            {"code": "velocity_exceeded_per_hour", "text": "Too many transactions", "context": {}},
        ]

        result = engine.calculate_risk(messages)

        assert 0 <= result.total_score <= 1
        assert result.level in RiskLevel
        assert len(result.factors) == 1

    def test_high_risk_triggers_block(self):
        from core.scoring.risk_engine import RiskEngine

        engine = RiskEngine()

        messages = [
            {"code": "account_takeover_risk", "text": "Account takeover", "context": {}},
            {"code": "impossible_travel_detected", "text": "Impossible travel", "context": {}},
            {"code": "aml_cft_limit_exceeded", "text": "AML limit exceeded", "context": {}},
        ]

        result = engine.calculate_risk(messages)

        assert result.total_score >= 0.7
        assert result.should_block or result.should_review

    def test_no_factors_returns_zero(self):
        from core.scoring.risk_engine import RiskEngine, RiskLevel

        engine = RiskEngine()
        result = engine.calculate_risk([])

        assert result.total_score == 0
        assert result.level == RiskLevel.LOW
        assert not result.should_block

    def test_recommendation_based_on_level(self):
        from core.scoring.risk_engine import RiskEngine

        engine = RiskEngine()

        low_risk = engine.calculate_risk([])
        assert "ALLOW" in low_risk.recommendation

        high_risk = engine.calculate_risk([
            {"code": "account_takeover_risk", "text": "ATO", "context": {}},
            {"code": "impossible_travel_detected", "text": "Travel", "context": {}},
        ])
        assert "BLOCK" in high_risk.recommendation or "REVIEW" in high_risk.recommendation


class TestImpossibleTravel:
    """Tests for impossible travel detection."""

    def test_haversine_distance(self):
        from core.audit.rules.impossible_travel_rule import ImpossibleTravelRule

        nyc = (40.7128, -74.0060)
        london = (51.5074, -0.1278)

        distance = ImpossibleTravelRule.haversine_distance(
            nyc[0], nyc[1], london[0], london[1]
        )

        assert 5500 < distance < 5700

    def test_same_location_zero_distance(self):
        from core.audit.rules.impossible_travel_rule import ImpossibleTravelRule

        distance = ImpossibleTravelRule.haversine_distance(
            40.7128, -74.0060, 40.7128, -74.0060
        )

        assert distance == 0
