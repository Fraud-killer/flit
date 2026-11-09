import json
import logging
import re

from django.http import JsonResponse
from core.security.rate_limiter import RateLimiter, RateLimitExceeded
from core.security.replay_protection import ReplayProtection, ReplayAttackDetected


logger = logging.getLogger(__name__)


class SecurityMiddleware:
    EXEMPT_PATHS = [
        "/admin/",
        "/static/",
        "/health/",
    ]

    RATE_LIMIT_ACTIONS = {
        "/api/v1/auth/": "authentication",
        "/api/v1/applications/": "api_general",
        "/api/v1/collect": "device_collection",
    }

    # Decisions have their own, wider bucket: a merchant's checkout sends one
    # audit per payment, and sharing the general limit would throttle the
    # thing FLIT is for.
    AUDIT_PATH = re.compile(r"^/api/v1/applications/(?P<application_id>[^/]+)/audit-")

    # An application's own audit limit is read on every call, so briefly kept.
    AUDIT_LIMIT_CACHE_SECONDS = 60

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        for exempt_path in self.EXEMPT_PATHS:
            if request.path.startswith(exempt_path):
                return self.get_response(request)

        try:
            rate_limit_info = self._check_rate_limit(request)
        except RateLimitExceeded as e:
            self._record_breach(request, e)
            return self._rate_limit_response(e)

        response = self.get_response(request)

        if rate_limit_info:
            response["X-RateLimit-Limit"] = rate_limit_info["limit"]
            response["X-RateLimit-Remaining"] = rate_limit_info["remaining"]
            response["X-RateLimit-Reset"] = rate_limit_info["reset"]

        return response

    def _check_rate_limit(self, request):
        client_id = RateLimiter.get_client_identifier(request)

        action = "api_general"
        audit = self.AUDIT_PATH.match(request.path)
        if audit:
            action = "api_audit"
            return RateLimiter.check(client_id, action, self._audit_config(audit["application_id"]))

        for path_prefix, action_name in self.RATE_LIMIT_ACTIONS.items():
            if request.path.startswith(path_prefix):
                action = action_name
                break

        return RateLimiter.check(client_id, action)

    @classmethod
    def _audit_config(cls, application_id):
        """
        The application's audit limit, or None for the default. Read before
        the request is authenticated, so a bad signature on a bank's path gets
        the bank's bucket. It still fails at the signature check.
        """
        from django.core.cache import cache
        from core.models import Application
        from core.security.rate_limiter import RateLimitConfig

        try:
            key = f"flit:auditlimit:{application_id[:64]}"
            limit = cache.get(key)
            if limit is None:
                limit = (
                    Application.objects.filter(id=application_id)
                    .values_list("audit_rate_limit_per_minute", flat=True).first()
                ) or 0
                cache.set(key, limit, cls.AUDIT_LIMIT_CACHE_SECONDS)
            return RateLimitConfig(requests=limit, window_seconds=60) if limit else None
        except Exception:
            return None

    def _record_breach(self, request, error):
        """
        A rate-limit breach is a signal, not just a refusal. Written to the
        audit log so the session scorer sees an origin that is probing faster
        than the API allows. Never fails the response.
        """
        try:
            from core.audit.logger import AuditLogger

            application_id = self._application_id(request)

            AuditLogger.log_security_event(
                "rate_limited",
                ip_address=RateLimiter.client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500] or None,
                application_id=application_id,
                context=dict(
                    path=request.path[:500],
                    method=request.method,
                    limit=error.limit,
                    window=error.window,
                    retry_after=error.retry_after,
                ),
            )
        except Exception:
            logger.warning("Could not record rate-limit breach", exc_info=True)

    @staticmethod
    def _application_id(request):
        """The application an HMAC-signed request claims to be, unverified."""
        import uuid

        claimed = claimed_application_id(request)
        if not claimed:
            return None
        try:
            return uuid.UUID(claimed)
        except ValueError:
            return None


    def _rate_limit_response(self, error: RateLimitExceeded):
        return JsonResponse(
            {
                "ok": False,
                "errors": [
                    {
                        "code": "rate_limit_exceeded",
                        "message": f"Too many requests. Limit: {error.limit} per {error.window}s",
                        "context": {
                            "limit": error.limit,
                            "window": error.window,
                            "retry_after": error.retry_after,
                        },
                    }
                ],
            },
            status=429,
            headers={
                "Retry-After": str(error.retry_after),
                "X-RateLimit-Limit": str(error.limit),
                "X-RateLimit-Remaining": "0",
            },
        )


class ReplayProtectionMiddleware:
    PROTECTED_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

    PROTECTED_PATHS = [
        "/api/v1/applications/",
    ]

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not self._should_protect(request):
            return self.get_response(request)

        application_id = self._extract_application_id(request)
        if not application_id:
            return self.get_response(request)

        try:
            ReplayProtection.validate(request, application_id)
        except ReplayAttackDetected as e:
            return self._replay_attack_response(e)

        return self.get_response(request)

    def _should_protect(self, request):
        if request.method not in self.PROTECTED_METHODS:
            return False

        for protected_path in self.PROTECTED_PATHS:
            if request.path.startswith(protected_path):
                return True

        return False

    def _extract_application_id(self, request):
        return claimed_application_id(request)

    def _replay_attack_response(self, error: ReplayAttackDetected):
        return JsonResponse(
            {
                "ok": False,
                "errors": [
                    {
                        "code": "replay_attack_detected",
                        "message": "Request rejected due to replay attack protection",
                        "context": {
                            "reason": error.reason,
                        },
                    }
                ],
            },
            status=400,
        )


def claimed_application_id(request):
    """
    The application id in `Authorization: HMAC-SHA256 {app_id}:{signature}`,
    or None. A claim, not a verified identity: the signature is checked by
    HmacAuthentication later. Enough to key a nonce or a log row on.
    """
    header = request.headers.get("Authorization", "") if hasattr(request, "headers") else ""
    if not isinstance(header, str) or not header.startswith("HMAC-SHA256"):
        return None
    credentials = header.split(" ", 1)[1].strip() if " " in header else ""
    application_id = credentials.split(":", 1)[0].strip()
    return application_id or None
