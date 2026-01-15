"""
Pytest configuration for FLIT tests.
"""

import os
import sys
import django
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kernel.settings")
os.environ.setdefault("DATABASE_URL", "sqlite:///test.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("MCRYPT_KEY", "kTMwZPVNixtc_nI4sqJcV4sybRlQZFb6P7LWE_ZNR6g=")
os.environ.setdefault("DEBUG", "true")


def pytest_configure():
    django.setup()


@pytest.fixture
def mock_cache():
    """Mock Django cache."""
    from unittest.mock import MagicMock, patch
    
    with patch("django.core.cache.cache") as mock:
        mock.get.return_value = None
        mock.set.return_value = None
        yield mock


@pytest.fixture
def request_factory():
    """Django request factory."""
    from django.test import RequestFactory
    return RequestFactory()


@pytest.fixture
def sample_transaction_event():
    """Sample transaction event for testing."""
    from devkit.struct import Struct
    
    return Struct(
        client_id="user_123",
        device_fingerprint="fp_abc123",
        amount="1000.00",
        currency_code="USD",
        latitude=40.7128,
        longitude=-74.0060,
        event_type="transaction",
    )


@pytest.fixture
def sample_policy():
    """Sample policy for testing."""
    from unittest.mock import MagicMock
    
    policy = MagicMock()
    policy.application.id = "550e8400-e29b-41d4-a716-446655440000"
    policy.aml_cft_limit = "10000 USD"
    policy.device_validity_days = 30
    policy.velocity_thresholds = {
        "transactions_per_minute": 5,
        "transactions_per_hour": 50,
    }
    return policy
