import time
import hashlib
from typing import Optional
from dataclasses import dataclass
from django.core.cache import cache


class RateLimitExceeded(Exception):
    def __init__(self, limit: int, window: int, retry_after: int):
        self.limit = limit
        self.window = window
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded: {limit} requests per {window}s")


@dataclass
class RateLimitConfig:
    requests: int
    window_seconds: int
    block_duration_seconds: Optional[int] = None


class RateLimiter:
    DEFAULT_CONFIGS = {
        "authentication": RateLimitConfig(requests=5, window_seconds=60, block_duration_seconds=300),
        "api_general": RateLimitConfig(requests=100, window_seconds=60),
        "api_audit": RateLimitConfig(requests=1000, window_seconds=60),
        "device_registration": RateLimitConfig(requests=10, window_seconds=60),
        # Public, unauthenticated: one browser sends a handful of visits.
        "device_collection": RateLimitConfig(requests=60, window_seconds=60),
        "high_risk_action": RateLimitConfig(requests=3, window_seconds=300, block_duration_seconds=600),
    }

    @classmethod
    def get_cache_key(cls, identifier: str, action: str) -> str:
        hashed = hashlib.sha256(f"{identifier}:{action}".encode()).hexdigest()[:16]
        return f"ratelimit:{action}:{hashed}"

    @classmethod
    def get_block_key(cls, identifier: str, action: str) -> str:
        hashed = hashlib.sha256(f"{identifier}:{action}".encode()).hexdigest()[:16]
        return f"ratelimit:blocked:{action}:{hashed}"

    @classmethod
    def check(
        cls,
        identifier: str,
        action: str,
        config: Optional[RateLimitConfig] = None,
    ) -> dict:
        if config is None:
            config = cls.DEFAULT_CONFIGS.get(action, cls.DEFAULT_CONFIGS["api_general"])

        block_key = cls.get_block_key(identifier, action)
        blocked_until = cache.get(block_key)

        if blocked_until:
            retry_after = int(blocked_until - time.time())
            if retry_after > 0:
                raise RateLimitExceeded(
                    limit=config.requests,
                    window=config.window_seconds,
                    retry_after=retry_after,
                )
            cache.delete(block_key)

        cache_key = cls.get_cache_key(identifier, action)
        current_time = time.time()
        window_start = current_time - config.window_seconds

        request_times = cache.get(cache_key, [])
        request_times = [t for t in request_times if t > window_start]

        if len(request_times) >= config.requests:
            if config.block_duration_seconds:
                cache.set(
                    block_key,
                    current_time + config.block_duration_seconds,
                    timeout=config.block_duration_seconds,
                )
                retry_after = config.block_duration_seconds
            else:
                oldest_request = min(request_times)
                retry_after = int(oldest_request + config.window_seconds - current_time) + 1

            raise RateLimitExceeded(
                limit=config.requests,
                window=config.window_seconds,
                retry_after=retry_after,
            )

        request_times.append(current_time)
        cache.set(cache_key, request_times, timeout=config.window_seconds + 1)

        return {
            "remaining": config.requests - len(request_times),
            "limit": config.requests,
            "reset": int(current_time + config.window_seconds),
        }

    @classmethod
    def reset(cls, identifier: str, action: str) -> None:
        cache_key = cls.get_cache_key(identifier, action)
        block_key = cls.get_block_key(identifier, action)
        cache.delete(cache_key)
        cache.delete(block_key)

    @classmethod
    def client_ip(cls, request) -> str:
        """
        The end client's address, as far as FLIT can trust it.

        X-Forwarded-For is a list the client starts and each proxy appends
        to. Only the entries written by proxies FLIT knows about are
        trustworthy: with TRUSTED_PROXY_DEPTH set to N, that is the Nth from
        the right. Depth 0 means no proxy, so the socket address is the
        client. Unset keeps the legacy first-entry reading.
        """
        remote = request.META.get("REMOTE_ADDR", "unknown")
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
        depth = cls.trusted_proxy_depth()

        if depth == 0 or not forwarded:
            return remote

        entries = [entry.strip() for entry in forwarded.split(",") if entry.strip()]
        if not entries:
            return remote

        if depth is None:
            return entries[0]

        return entries[-depth] if len(entries) >= depth else entries[0]

    @staticmethod
    def trusted_proxy_depth():
        from kernel.config import Config

        try:
            return Config.trusted_proxy_depth
        except Exception:
            return None

    @classmethod
    def get_client_identifier(cls, request) -> str:
        ip = cls.client_ip(request)

        user_agent = request.META.get("HTTP_USER_AGENT", "")
        fingerprint = request.headers.get("X-Device-Fingerprint", "")

        identifier_parts = [ip]
        if fingerprint:
            identifier_parts.append(fingerprint)
        else:
            identifier_parts.append(hashlib.md5(user_agent.encode()).hexdigest()[:8])

        return ":".join(identifier_parts)
