"""
Pytest configuration for FLIT tests.
"""

import os
import sys
from cryptography.fernet import Fernet
import django
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kernel.settings")
os.environ.setdefault("DATABASE_URL", "sqlite:///test.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("MCRYPT_KEY", Fernet.generate_key().decode())
os.environ.setdefault("DEBUG", "true")


def pytest_configure():
    django.setup()


@pytest.fixture(scope="session")
def test_database():
    """
    Create the test database once per session. Avoids pytest-django, whose
    plugin conflicted with this project's own django.setup().
    """
    from django.db import connection
    from django.test.utils import setup_test_environment, teardown_test_environment

    setup_test_environment()
    configuration = connection.creation.create_test_db(verbosity=0)

    yield

    connection.creation.destroy_test_db(configuration, verbosity=0)
    teardown_test_environment()


@pytest.fixture
def db(test_database):
    """A clean database for one test."""
    from django.core.management import call_command

    yield

    call_command("flush", interactive=False, verbosity=0, allow_cascade=True)


@pytest.fixture
def application(db):
    """An Application (with the Policy its post_save signal creates)."""
    from core.models import User, Organization, Application

    user = User.objects.create_user(email="owner@flit.io", password="x" * 12)
    organization = Organization.objects.create(name="Test Org", owner=user)

    return Application.objects.create(name="Test App", organization=organization)


@pytest.fixture
def second_application(db):
    """A second Application, to check one merchant cannot see another's data."""
    from core.models import User, Organization, Application

    user = User.objects.create_user(email="other@flit.io", password="x" * 12)
    organization = Organization.objects.create(name="Other Org", owner=user)

    return Application.objects.create(name="Other App", organization=organization)


@pytest.fixture
def no_geoip():
    """No GeoIP databases, so IP lookups return nothing."""
    from core.intelligence.ip_intelligence import GeoIPDatabase

    previous = GeoIPDatabase._readers
    GeoIPDatabase._readers = {}
    yield
    GeoIPDatabase._readers = previous


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
