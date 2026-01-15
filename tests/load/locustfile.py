"""
FLIT Load Testing with Locust

Usage:
    # Install locust
    pip install locust

    # Run load test (web UI)
    locust -f tests/load/locustfile.py --host=http://localhost:18000

    # Run headless (CLI)
    locust -f tests/load/locustfile.py --host=http://localhost:18000 \
        --headless -u 100 -r 10 -t 5m

    # Run with specific user class
    locust -f tests/load/locustfile.py --host=http://localhost:18000 \
        AuditUser --headless -u 50 -r 5 -t 2m
"""

import json
import time
import uuid
import hmac
import random
import hashlib
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner


def generate_hmac_signature(secret_key: str, message_hash: str) -> str:
    """Generate HMAC-SHA256 signature."""
    signature = hmac.new(
        secret_key.encode(),
        message_hash.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature


def create_message_hash(method: str, path: str, body: dict, timestamp: str, content_type: str) -> str:
    """Create message hash for HMAC authentication."""
    body_hash = hashlib.sha256(json.dumps(body).encode()).hexdigest()
    message = {
        "path": path.lower(),
        "method": method.lower(),
        "body_hash": body_hash,
        "timestamp": timestamp,
        "content_type": content_type,
    }
    return hashlib.sha256(json.dumps(message, sort_keys=True).encode()).hexdigest()


class FLITBaseUser(HttpUser):
    """Base user class with authentication helpers."""
    
    abstract = True
    
    APPLICATION_ID = "test-app-id"
    SECRET_KEY = "test-secret-key"
    
    def get_auth_headers(self, method: str, path: str, body: dict) -> dict:
        """Generate authentication headers for API requests."""
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        content_type = "application/json"
        
        message_hash = create_message_hash(method, path, body, timestamp, content_type)
        signature = generate_hmac_signature(self.SECRET_KEY, message_hash)
        
        return {
            "Authorization": f"HMAC-SHA256 {self.APPLICATION_ID}:{signature}",
            "Content-Type": content_type,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
        }


class AuditUser(FLITBaseUser):
    """Simulates users making audit requests."""
    
    wait_time = between(0.1, 0.5)
    
    def on_start(self):
        """Initialize user session."""
        self.client_ids = [f"user_{i}" for i in range(100)]
        self.device_fingerprints = [f"fp_{uuid.uuid4().hex[:12]}" for _ in range(50)]
        self.currencies = ["USD", "EUR", "GBP", "NGN", "KES"]
        self.countries = [
            ("US", 40.7128, -74.0060),
            ("GB", 51.5074, -0.1278),
            ("NG", 6.5244, 3.3792),
            ("KE", -1.2921, 36.8219),
            ("DE", 52.5200, 13.4050),
        ]
    
    @task(10)
    def audit_transaction(self):
        """Audit a transaction - most common operation."""
        path = f"/api/v1/applications/{self.APPLICATION_ID}/audit-transaction"
        
        country = random.choice(self.countries)
        body = {
            "client_id": random.choice(self.client_ids),
            "device_fingerprint": random.choice(self.device_fingerprints),
            "amount": str(round(random.uniform(10, 10000), 2)),
            "currency_code": random.choice(self.currencies),
            "latitude": country[1] + random.uniform(-0.1, 0.1),
            "longitude": country[2] + random.uniform(-0.1, 0.1),
            "transaction_type": random.choice(["debit", "credit"]),
        }
        
        headers = self.get_auth_headers("POST", path, body)
        
        with self.client.post(
            path,
            json=body,
            headers=headers,
            name="/api/v1/applications/{id}/audit-transaction",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                data = response.json()
                if data.get("ok"):
                    response.success()
                else:
                    response.failure(f"API error: {data.get('errors')}")
            elif response.status_code == 429:
                response.failure("Rate limited")
            else:
                response.failure(f"HTTP {response.status_code}")
    
    @task(3)
    def audit_login(self):
        """Audit a login event."""
        path = f"/api/v1/applications/{self.APPLICATION_ID}/audit-login"
        
        country = random.choice(self.countries)
        body = {
            "client_id": random.choice(self.client_ids),
            "device_fingerprint": random.choice(self.device_fingerprints),
            "ip_address": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}",
            "latitude": country[1],
            "longitude": country[2],
        }
        
        headers = self.get_auth_headers("POST", path, body)
        
        self.client.post(
            path,
            json=body,
            headers=headers,
            name="/api/v1/applications/{id}/audit-login",
        )


class DeviceRegistrationUser(FLITBaseUser):
    """Simulates device registration flows."""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        self.client_ids = [f"new_user_{uuid.uuid4().hex[:8]}" for _ in range(20)]
    
    @task
    def register_device(self):
        """Register a new device."""
        path = f"/api/v1/applications/{self.APPLICATION_ID}/register-device"
        
        body = {
            "client_id": random.choice(self.client_ids),
            "visit_id": f"visit_{uuid.uuid4().hex}",
        }
        
        headers = self.get_auth_headers("POST", path, body)
        
        self.client.post(
            path,
            json=body,
            headers=headers,
            name="/api/v1/applications/{id}/register-device",
        )


class MixedWorkloadUser(FLITBaseUser):
    """Simulates realistic mixed workload."""
    
    wait_time = between(0.5, 2)
    
    def on_start(self):
        self.client_id = f"user_{uuid.uuid4().hex[:8]}"
        self.device_fingerprint = f"fp_{uuid.uuid4().hex[:12]}"
        self.session_start = time.time()
    
    @task(20)
    def normal_transaction(self):
        """Normal transaction - low risk."""
        self._audit_transaction(
            amount=random.uniform(10, 500),
            same_location=True,
        )
    
    @task(5)
    def high_value_transaction(self):
        """High value transaction - elevated risk."""
        self._audit_transaction(
            amount=random.uniform(5000, 50000),
            same_location=True,
        )
    
    @task(1)
    def suspicious_transaction(self):
        """Suspicious transaction - different location."""
        self._audit_transaction(
            amount=random.uniform(1000, 5000),
            same_location=False,
        )
    
    def _audit_transaction(self, amount: float, same_location: bool):
        path = f"/api/v1/applications/{self.APPLICATION_ID}/audit-transaction"
        
        if same_location:
            lat, lon = 40.7128, -74.0060
        else:
            lat = random.uniform(-90, 90)
            lon = random.uniform(-180, 180)
        
        body = {
            "client_id": self.client_id,
            "device_fingerprint": self.device_fingerprint,
            "amount": str(round(amount, 2)),
            "currency_code": "USD",
            "latitude": lat,
            "longitude": lon,
        }
        
        headers = self.get_auth_headers("POST", path, body)
        
        self.client.post(
            path,
            json=body,
            headers=headers,
            name="/api/v1/applications/{id}/audit-transaction",
        )


class RateLimitTestUser(FLITBaseUser):
    """Tests rate limiting behavior."""
    
    wait_time = between(0.01, 0.05)
    
    @task
    def rapid_fire_requests(self):
        """Send rapid requests to trigger rate limiting."""
        path = f"/api/v1/applications/{self.APPLICATION_ID}/audit-transaction"
        
        body = {
            "client_id": "rate_limit_test",
            "amount": "100.00",
            "currency_code": "USD",
        }
        
        headers = self.get_auth_headers("POST", path, body)
        
        with self.client.post(
            path,
            json=body,
            headers=headers,
            name="rate-limit-test",
            catch_response=True,
        ) as response:
            if response.status_code == 429:
                response.success()
            elif response.status_code == 200:
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when test starts."""
    print("=" * 60)
    print("FLIT Load Test Starting")
    print("=" * 60)
    if isinstance(environment.runner, MasterRunner):
        print("Running in distributed mode (master)")
    else:
        print("Running in standalone mode")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when test stops."""
    print("=" * 60)
    print("FLIT Load Test Complete")
    print("=" * 60)
    
    stats = environment.stats
    print(f"\nTotal Requests: {stats.total.num_requests}")
    print(f"Failed Requests: {stats.total.num_failures}")
    print(f"Median Response Time: {stats.total.median_response_time}ms")
    print(f"95th Percentile: {stats.total.get_response_time_percentile(0.95)}ms")
    print(f"99th Percentile: {stats.total.get_response_time_percentile(0.99)}ms")
    print(f"Requests/sec: {stats.total.total_rps:.2f}")
