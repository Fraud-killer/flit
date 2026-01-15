import json
from django.http import JsonResponse
from core.security.rate_limiter import RateLimiter, RateLimitExceeded
from core.security.replay_protection import ReplayProtection, ReplayAttackDetected


class SecurityMiddleware:
    EXEMPT_PATHS = [
        "/admin/",
        "/static/",
        "/health/",
    ]

    RATE_LIMIT_ACTIONS = {
        "/api/v1/auth/": "authentication",
        "/api/v1/applications/": "api_general",
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        for exempt_path in self.EXEMPT_PATHS:
            if request.path.startswith(exempt_path):
                return self.get_response(request)

        try:
            rate_limit_info = self._check_rate_limit(request)
        except RateLimitExceeded as e:
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
        for path_prefix, action_name in self.RATE_LIMIT_ACTIONS.items():
            if request.path.startswith(path_prefix):
                action = action_name
                break

        return RateLimiter.check(client_id, action)

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
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("HMAC-SHA256"):
            parts = auth_header.split(":")
            if len(parts) >= 2:
                return parts[1]
        return None

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
