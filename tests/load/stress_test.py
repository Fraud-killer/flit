"""
FLIT Stress Testing Script

Direct stress testing without Locust for quick validation.

Usage:
    python tests/load/stress_test.py --host http://localhost:18000 --users 50 --duration 60
"""

import argparse
import asyncio
import aiohttp
import json
import time
import uuid
import hmac
import hashlib
import random
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor


@dataclass
class StressTestResult:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_requests: int = 0
    response_times: List[float] = field(default_factory=list)
    errors: Dict[str, int] = field(default_factory=dict)
    start_time: float = 0
    end_time: float = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def requests_per_second(self) -> float:
        return self.total_requests / self.duration if self.duration > 0 else 0

    @property
    def success_rate(self) -> float:
        return (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0

    @property
    def avg_response_time(self) -> float:
        return statistics.mean(self.response_times) if self.response_times else 0

    @property
    def p50_response_time(self) -> float:
        return statistics.median(self.response_times) if self.response_times else 0

    @property
    def p95_response_time(self) -> float:
        if not self.response_times:
            return 0
        sorted_times = sorted(self.response_times)
        idx = int(len(sorted_times) * 0.95)
        return sorted_times[idx]

    @property
    def p99_response_time(self) -> float:
        if not self.response_times:
            return 0
        sorted_times = sorted(self.response_times)
        idx = int(len(sorted_times) * 0.99)
        return sorted_times[idx]

    def print_report(self):
        print("\n" + "=" * 60)
        print("STRESS TEST RESULTS")
        print("=" * 60)
        print(f"Duration:              {self.duration:.2f}s")
        print(f"Total Requests:        {self.total_requests}")
        print(f"Successful:            {self.successful_requests}")
        print(f"Failed:                {self.failed_requests}")
        print(f"Rate Limited:          {self.rate_limited_requests}")
        print(f"Success Rate:          {self.success_rate:.2f}%")
        print(f"Requests/sec:          {self.requests_per_second:.2f}")
        print("-" * 60)
        print("Response Times:")
        print(f"  Average:             {self.avg_response_time:.2f}ms")
        print(f"  Median (p50):        {self.p50_response_time:.2f}ms")
        print(f"  95th Percentile:     {self.p95_response_time:.2f}ms")
        print(f"  99th Percentile:     {self.p99_response_time:.2f}ms")
        if self.errors:
            print("-" * 60)
            print("Errors:")
            for error, count in sorted(self.errors.items(), key=lambda x: -x[1]):
                print(f"  {error}: {count}")
        print("=" * 60)


class StressTester:
    def __init__(
        self,
        host: str,
        application_id: str = "550e8400-e29b-41d4-a716-446655440000",
        secret_key: str = "test-secret-key-12345",
    ):
        self.host = host.rstrip("/")
        self.application_id = application_id
        self.secret_key = secret_key
        self.result = StressTestResult()

    def _generate_signature(self, message_hash: str) -> str:
        return hmac.new(
            self.secret_key.encode(),
            message_hash.encode(),
            hashlib.sha256
        ).hexdigest()

    def _create_message_hash(self, method: str, path: str, body: dict, timestamp: str) -> str:
        body_hash = hashlib.sha256(json.dumps(body).encode()).hexdigest()
        message = {
            "path": path.lower(),
            "method": method.lower(),
            "body_hash": body_hash,
            "timestamp": timestamp,
            "content_type": "application/json",
        }
        return hashlib.sha256(json.dumps(message, sort_keys=True).encode()).hexdigest()

    def _get_headers(self, method: str, path: str, body: dict) -> dict:
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        message_hash = self._create_message_hash(method, path, body, timestamp)
        signature = self._generate_signature(message_hash)

        return {
            "Authorization": f"HMAC-SHA256 {self.application_id}:{signature}",
            "Content-Type": "application/json",
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
        }

    def _generate_transaction_payload(self) -> dict:
        locations = [
            (40.7128, -74.0060),
            (51.5074, -0.1278),
            (6.5244, 3.3792),
            (35.6762, 139.6503),
            (52.5200, 13.4050),
        ]
        lat, lon = random.choice(locations)

        return {
            "client_id": f"user_{random.randint(1, 100)}",
            "device_fingerprint": f"fp_{uuid.uuid4().hex[:12]}",
            "amount": str(round(random.uniform(10, 10000), 2)),
            "currency_code": random.choice(["USD", "EUR", "GBP", "NGN"]),
            "latitude": lat + random.uniform(-0.1, 0.1),
            "longitude": lon + random.uniform(-0.1, 0.1),
        }

    async def _make_request(self, session: aiohttp.ClientSession) -> None:
        path = f"/api/v1/applications/{self.application_id}/audit-transaction"
        url = f"{self.host}{path}"
        body = self._generate_transaction_payload()
        headers = self._get_headers("POST", path, body)

        start_time = time.time()
        try:
            async with session.post(url, json=body, headers=headers, timeout=30) as response:
                response_time = (time.time() - start_time) * 1000
                self.result.response_times.append(response_time)
                self.result.total_requests += 1

                if response.status == 200:
                    data = await response.json()
                    if data.get("ok"):
                        self.result.successful_requests += 1
                    else:
                        self.result.failed_requests += 1
                        error = str(data.get("errors", "Unknown error"))[:50]
                        self.result.errors[error] = self.result.errors.get(error, 0) + 1
                elif response.status == 429:
                    self.result.rate_limited_requests += 1
                    self.result.total_requests += 1
                else:
                    self.result.failed_requests += 1
                    error = f"HTTP {response.status}"
                    self.result.errors[error] = self.result.errors.get(error, 0) + 1

        except asyncio.TimeoutError:
            self.result.failed_requests += 1
            self.result.total_requests += 1
            self.result.errors["Timeout"] = self.result.errors.get("Timeout", 0) + 1
        except Exception as e:
            self.result.failed_requests += 1
            self.result.total_requests += 1
            error = str(type(e).__name__)
            self.result.errors[error] = self.result.errors.get(error, 0) + 1

    async def _worker(self, session: aiohttp.ClientSession, duration: float):
        end_time = time.time() + duration
        while time.time() < end_time:
            await self._make_request(session)
            await asyncio.sleep(random.uniform(0.01, 0.1))

    async def run_async(self, num_users: int, duration: float):
        print(f"\nStarting stress test:")
        print(f"  Host: {self.host}")
        print(f"  Concurrent Users: {num_users}")
        print(f"  Duration: {duration}s")
        print("\nRunning...\n")

        connector = aiohttp.TCPConnector(limit=num_users * 2)
        timeout = aiohttp.ClientTimeout(total=30)

        self.result.start_time = time.time()

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self._worker(session, duration) for _ in range(num_users)]
            await asyncio.gather(*tasks)

        self.result.end_time = time.time()
        self.result.print_report()

    def run(self, num_users: int, duration: float):
        asyncio.run(self.run_async(num_users, duration))


class VelocityStressTester(StressTester):
    """Tests velocity detection by sending rapid requests from same user."""

    async def run_velocity_test(self, requests_per_user: int = 100):
        print("\nVelocity Detection Stress Test")
        print("=" * 60)

        connector = aiohttp.TCPConnector(limit=10)
        self.result.start_time = time.time()

        async with aiohttp.ClientSession(connector=connector) as session:
            client_id = f"velocity_test_{uuid.uuid4().hex[:8]}"

            for i in range(requests_per_user):
                path = f"/api/v1/applications/{self.application_id}/audit-transaction"
                url = f"{self.host}{path}"
                body = {
                    "client_id": client_id,
                    "device_fingerprint": "fp_velocity_test",
                    "amount": str(round(random.uniform(10, 100), 2)),
                    "currency_code": "USD",
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                }
                headers = self._get_headers("POST", path, body)

                start_time = time.time()
                try:
                    async with session.post(url, json=body, headers=headers) as response:
                        response_time = (time.time() - start_time) * 1000
                        self.result.response_times.append(response_time)
                        self.result.total_requests += 1

                        if response.status == 200:
                            data = await response.json()
                            risk_score = data.get("data", {}).get("risk_score", 0)
                            if risk_score > 0.5:
                                print(f"  Request {i+1}: Risk score {risk_score:.2f} - Velocity detected!")
                            self.result.successful_requests += 1
                        elif response.status == 429:
                            self.result.rate_limited_requests += 1
                            print(f"  Request {i+1}: Rate limited")
                        else:
                            self.result.failed_requests += 1

                except Exception as e:
                    self.result.failed_requests += 1
                    print(f"  Request {i+1}: Error - {e}")

        self.result.end_time = time.time()
        self.result.print_report()


class ImpossibleTravelTester(StressTester):
    """Tests impossible travel detection."""

    async def run_travel_test(self):
        print("\nImpossible Travel Detection Test")
        print("=" * 60)

        locations = [
            ("New York", 40.7128, -74.0060),
            ("London", 51.5074, -0.1278),
            ("Tokyo", 35.6762, 139.6503),
            ("Sydney", -33.8688, 151.2093),
        ]

        connector = aiohttp.TCPConnector(limit=10)
        client_id = f"travel_test_{uuid.uuid4().hex[:8]}"

        async with aiohttp.ClientSession(connector=connector) as session:
            for i, (city, lat, lon) in enumerate(locations):
                path = f"/api/v1/applications/{self.application_id}/audit-transaction"
                url = f"{self.host}{path}"
                body = {
                    "client_id": client_id,
                    "device_fingerprint": "fp_travel_test",
                    "amount": "100.00",
                    "currency_code": "USD",
                    "latitude": lat,
                    "longitude": lon,
                }
                headers = self._get_headers("POST", path, body)

                try:
                    async with session.post(url, json=body, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            risk_score = data.get("data", {}).get("risk_score", 0)
                            factors = data.get("data", {}).get("factors", [])
                            print(f"  {city}: Risk={risk_score:.2f}, Factors={factors}")
                        else:
                            print(f"  {city}: HTTP {response.status}")
                except Exception as e:
                    print(f"  {city}: Error - {e}")

                await asyncio.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="FLIT Stress Testing")
    parser.add_argument("--host", default="http://localhost:18000", help="API host URL")
    parser.add_argument("--users", type=int, default=50, help="Number of concurrent users")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--app-id", default="test-app-id", help="Application ID")
    parser.add_argument("--secret", default="test-secret-key", help="Secret key")
    parser.add_argument(
        "--test",
        choices=["load", "velocity", "travel", "all"],
        default="load",
        help="Test type to run",
    )

    args = parser.parse_args()

    if args.test == "load":
        tester = StressTester(args.host, args.app_id, args.secret)
        tester.run(args.users, args.duration)

    elif args.test == "velocity":
        tester = VelocityStressTester(args.host, args.app_id, args.secret)
        asyncio.run(tester.run_velocity_test(100))

    elif args.test == "travel":
        tester = ImpossibleTravelTester(args.host, args.app_id, args.secret)
        asyncio.run(tester.run_travel_test())

    elif args.test == "all":
        print("\n" + "=" * 60)
        print("RUNNING ALL STRESS TESTS")
        print("=" * 60)

        print("\n[1/3] Load Test")
        tester = StressTester(args.host, args.app_id, args.secret)
        tester.run(args.users, args.duration)

        print("\n[2/3] Velocity Test")
        tester = VelocityStressTester(args.host, args.app_id, args.secret)
        asyncio.run(tester.run_velocity_test(100))

        print("\n[3/3] Impossible Travel Test")
        tester = ImpossibleTravelTester(args.host, args.app_id, args.secret)
        asyncio.run(tester.run_travel_test())


if __name__ == "__main__":
    main()
