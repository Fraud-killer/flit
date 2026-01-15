import time
import hashlib
from typing import Optional
from django.core.cache import cache


class ReplayAttackDetected(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Replay attack detected: {reason}")


class ReplayProtection:
    NONCE_EXPIRY_SECONDS = 300
    TIMESTAMP_TOLERANCE_SECONDS = 30

    @classmethod
    def get_nonce_key(cls, nonce: str, application_id: str) -> str:
        return f"replay:nonce:{application_id}:{nonce}"

    @classmethod
    def get_request_hash_key(cls, request_hash: str) -> str:
        return f"replay:request:{request_hash}"

    @classmethod
    def validate_timestamp(cls, timestamp: Optional[str]) -> int:
        if not timestamp:
            raise ReplayAttackDetected("Missing timestamp header")

        try:
            request_time = int(timestamp)
        except (ValueError, TypeError):
            raise ReplayAttackDetected("Invalid timestamp format")

        current_time = int(time.time())
        time_diff = abs(current_time - request_time)

        if time_diff > cls.TIMESTAMP_TOLERANCE_SECONDS:
            raise ReplayAttackDetected(
                f"Timestamp outside tolerance window ({time_diff}s drift)"
            )

        return request_time

    @classmethod
    def validate_nonce(cls, nonce: Optional[str], application_id: str) -> None:
        if not nonce:
            raise ReplayAttackDetected("Missing nonce header")

        if len(nonce) < 16 or len(nonce) > 64:
            raise ReplayAttackDetected("Invalid nonce length")

        nonce_key = cls.get_nonce_key(nonce, application_id)

        if cache.get(nonce_key):
            raise ReplayAttackDetected("Nonce already used")

        cache.set(nonce_key, True, timeout=cls.NONCE_EXPIRY_SECONDS)

    @classmethod
    def compute_request_hash(
        cls,
        method: str,
        path: str,
        body: bytes,
        timestamp: str,
        nonce: str,
    ) -> str:
        content = f"{method}:{path}:{body.hex()}:{timestamp}:{nonce}"
        return hashlib.sha256(content.encode()).hexdigest()

    @classmethod
    def validate_request_uniqueness(cls, request_hash: str) -> None:
        hash_key = cls.get_request_hash_key(request_hash)

        if cache.get(hash_key):
            raise ReplayAttackDetected("Duplicate request detected")

        cache.set(hash_key, True, timeout=cls.NONCE_EXPIRY_SECONDS)

    @classmethod
    def validate(cls, request, application_id: str) -> dict:
        timestamp = request.headers.get("X-Timestamp")
        nonce = request.headers.get("X-Nonce")

        validated_timestamp = cls.validate_timestamp(timestamp)
        cls.validate_nonce(nonce, application_id)

        body = request.body if hasattr(request, "body") else b""
        request_hash = cls.compute_request_hash(
            method=request.method,
            path=request.path,
            body=body,
            timestamp=timestamp,
            nonce=nonce,
        )

        cls.validate_request_uniqueness(request_hash)

        return {
            "timestamp": validated_timestamp,
            "nonce": nonce,
            "request_hash": request_hash,
        }
