#!/usr/bin/env python
"""
Simple test runner for FLIT security components.
Bypasses pytest plugin conflicts.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "app"))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kernel.settings")
os.environ.setdefault("DATABASE_URL", "sqlite:///test.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("MCRYPT_KEY", "kTMwZPVNixtc_nI4sqJcV4sybRlQZFb6P7LWE_ZNR6g=")
os.environ.setdefault("DEBUG", "true")

import django
django.setup()

import time
from unittest.mock import Mock, patch, MagicMock


def run_test(name, test_func):
    try:
        test_func()
        print(f"  ✓ {name}")
        return True
    except AssertionError as e:
        print(f"  ✗ {name}: {e}")
        return False
    except Exception as e:
        print(f"  ✗ {name}: {type(e).__name__}: {e}")
        return False


class TestResults:
    passed = 0
    failed = 0


def test_rate_limiter_allows_requests():
    from core.security.rate_limiter import RateLimiter, RateLimitConfig
    
    with patch("core.security.rate_limiter.cache") as mock_cache:
        mock_cache.get.return_value = []
        config = RateLimitConfig(requests=10, window_seconds=60)
        result = RateLimiter.check("test_user", "api_general", config)
        assert result["remaining"] == 9
        assert result["limit"] == 10


def test_rate_limiter_blocks_exceeded():
    from core.security.rate_limiter import RateLimiter, RateLimitConfig, RateLimitExceeded
    
    with patch("core.security.rate_limiter.cache") as mock_cache:
        mock_cache.get.side_effect = [None, [time.time() - i for i in range(10)]]
        config = RateLimitConfig(requests=10, window_seconds=60)
        try:
            RateLimiter.check("test_user", "api_general", config)
            assert False, "Should have raised RateLimitExceeded"
        except RateLimitExceeded as e:
            assert e.limit == 10


def test_replay_validates_timestamp():
    from core.security.replay_protection import ReplayProtection
    current_time = str(int(time.time()))
    result = ReplayProtection.validate_timestamp(current_time)
    assert result == int(current_time)


def test_replay_rejects_missing_timestamp():
    from core.security.replay_protection import ReplayProtection, ReplayAttackDetected
    try:
        ReplayProtection.validate_timestamp(None)
        assert False, "Should have raised ReplayAttackDetected"
    except ReplayAttackDetected as e:
        assert "Missing timestamp" in str(e)


def test_replay_rejects_old_timestamp():
    from core.security.replay_protection import ReplayProtection, ReplayAttackDetected
    old_time = str(int(time.time()) - 120)
    try:
        ReplayProtection.validate_timestamp(old_time)
        assert False, "Should have raised ReplayAttackDetected"
    except ReplayAttackDetected as e:
        assert "outside tolerance" in str(e)


def test_request_validator_sanitizes():
    from core.security.request_validator import RequestValidator
    result = RequestValidator.sanitize_string("  hello world  ")
    assert result == "hello world"


def test_request_validator_truncates():
    from core.security.request_validator import RequestValidator
    long_string = "a" * 2000
    result = RequestValidator.sanitize_string(long_string, max_length=100)
    assert len(result) == 100


def test_request_validator_detects_xss():
    from core.security.request_validator import RequestValidator
    dangerous = "<script>alert('xss')</script>"
    result = RequestValidator.check_dangerous_content(dangerous)
    assert result is not None


def test_request_validator_detects_sql():
    from core.security.request_validator import RequestValidator
    dangerous = "'; DROP TABLE users; --"
    result = RequestValidator.check_dangerous_content(dangerous)
    assert result is not None


def test_request_validator_uuid():
    from core.security.request_validator import RequestValidator
    valid = "550e8400-e29b-41d4-a716-446655440000"
    assert RequestValidator.validate_uuid(valid, "id") is None
    assert RequestValidator.validate_uuid("not-uuid", "id") is not None


def test_ip_intelligence_private():
    from core.intelligence.ip_intelligence import IPIntelligence
    assert IPIntelligence._is_private_ip("192.168.1.1")
    assert IPIntelligence._is_private_ip("10.0.0.1")
    assert not IPIntelligence._is_private_ip("8.8.8.8")


def test_bot_detection_googlebot():
    from core.intelligence.bot_detection import BotDetector
    result = BotDetector.detect("Googlebot/2.1")
    assert result.is_bot
    assert result.bot_type == "search_crawler"


def test_bot_detection_curl():
    from core.intelligence.bot_detection import BotDetector
    result = BotDetector.detect("curl/7.68.0")
    assert result.is_bot
    assert result.bot_type == "http_client"


def test_bot_detection_missing_ua():
    from core.intelligence.bot_detection import BotDetector
    result = BotDetector.detect(None)
    assert "missing_user_agent" in result.signals


def test_bot_detection_legitimate():
    from core.intelligence.bot_detection import BotDetector
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0"
    result = BotDetector.detect(ua)
    assert not result.is_bot


def test_risk_engine_calculates():
    from core.scoring.risk_engine import RiskEngine, RiskLevel
    engine = RiskEngine()
    messages = [{"code": "velocity_exceeded_per_hour", "text": "Too many", "context": {}}]
    result = engine.calculate_risk(messages)
    assert 0 <= result.total_score <= 1
    assert result.level in RiskLevel


def test_risk_engine_empty():
    from core.scoring.risk_engine import RiskEngine, RiskLevel
    engine = RiskEngine()
    result = engine.calculate_risk([])
    assert result.total_score == 0
    assert result.level == RiskLevel.LOW


def test_impossible_travel_distance():
    from core.audit.rules.impossible_travel_rule import ImpossibleTravelRule
    nyc = (40.7128, -74.0060)
    london = (51.5074, -0.1278)
    distance = ImpossibleTravelRule.haversine_distance(nyc[0], nyc[1], london[0], london[1])
    assert 5500 < distance < 5700


def test_impossible_travel_same_location():
    from core.audit.rules.impossible_travel_rule import ImpossibleTravelRule
    distance = ImpossibleTravelRule.haversine_distance(40.7128, -74.0060, 40.7128, -74.0060)
    assert distance == 0


def main():
    print("\n" + "=" * 60)
    print("FLIT SECURITY UNIT TESTS")
    print("=" * 60 + "\n")

    tests = [
        ("Rate limiter allows requests under limit", test_rate_limiter_allows_requests),
        ("Rate limiter blocks when exceeded", test_rate_limiter_blocks_exceeded),
        ("Replay protection validates timestamp", test_replay_validates_timestamp),
        ("Replay protection rejects missing timestamp", test_replay_rejects_missing_timestamp),
        ("Replay protection rejects old timestamp", test_replay_rejects_old_timestamp),
        ("Request validator sanitizes strings", test_request_validator_sanitizes),
        ("Request validator truncates long strings", test_request_validator_truncates),
        ("Request validator detects XSS", test_request_validator_detects_xss),
        ("Request validator detects SQL injection", test_request_validator_detects_sql),
        ("Request validator validates UUID", test_request_validator_uuid),
        ("IP intelligence detects private IPs", test_ip_intelligence_private),
        ("Bot detection identifies Googlebot", test_bot_detection_googlebot),
        ("Bot detection identifies curl", test_bot_detection_curl),
        ("Bot detection flags missing user agent", test_bot_detection_missing_ua),
        ("Bot detection allows legitimate browser", test_bot_detection_legitimate),
        ("Risk engine calculates scores", test_risk_engine_calculates),
        ("Risk engine handles empty input", test_risk_engine_empty),
        ("Impossible travel calculates distance", test_impossible_travel_distance),
        ("Impossible travel same location is zero", test_impossible_travel_same_location),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        if run_test(name, test_func):
            passed += 1
        else:
            failed += 1

    print("\n" + "-" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60 + "\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
