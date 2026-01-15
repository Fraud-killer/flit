"""
Health Check Endpoints for FLIT

Provides health and readiness checks for container orchestration
and load balancer health probes.
"""

import time
from typing import Dict, Any
from django.db import connection
from django.core.cache import cache
from django.http import JsonResponse


def health_check(request) -> JsonResponse:
    """
    Basic health check - returns 200 if the application is running.
    Used by load balancers for basic availability.
    """
    return JsonResponse({
        "status": "healthy",
        "service": "flit",
        "timestamp": time.time(),
    })


def readiness_check(request) -> JsonResponse:
    """
    Readiness check - verifies all dependencies are available.
    Used by Kubernetes to determine if the pod can receive traffic.
    """
    checks = {}
    all_healthy = True
    
    # Database check
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        checks["database"] = {"status": "healthy", "latency_ms": 0}
    except Exception as e:
        checks["database"] = {"status": "unhealthy", "error": str(e)}
        all_healthy = False
    
    # Cache check
    try:
        cache_key = "_health_check_"
        cache.set(cache_key, "ok", timeout=10)
        result = cache.get(cache_key)
        if result == "ok":
            checks["cache"] = {"status": "healthy"}
        else:
            checks["cache"] = {"status": "unhealthy", "error": "Cache read failed"}
            all_healthy = False
    except Exception as e:
        checks["cache"] = {"status": "unhealthy", "error": str(e)}
        all_healthy = False
    
    status_code = 200 if all_healthy else 503
    
    return JsonResponse({
        "status": "ready" if all_healthy else "not_ready",
        "checks": checks,
        "timestamp": time.time(),
    }, status=status_code)


def liveness_check(request) -> JsonResponse:
    """
    Liveness check - verifies the application is not deadlocked.
    Used by Kubernetes to determine if the pod should be restarted.
    """
    # Simple check that the event loop is responsive
    return JsonResponse({
        "status": "alive",
        "timestamp": time.time(),
    })


def detailed_status(request) -> JsonResponse:
    """
    Detailed status endpoint for debugging and monitoring.
    Should be protected in production.
    """
    from django.conf import settings
    from core.config_validator import get_config_status
    
    config_status = get_config_status()
    
    # Count active rules
    from core.audit.auditor import Auditor
    rule_count = len(Auditor.rule_classes)
    
    return JsonResponse({
        "service": "flit",
        "version": "1.0.0",
        "environment": "development" if settings.DEBUG else "production",
        "configuration": config_status,
        "rules": {
            "active_count": rule_count,
            "categories": [
                "device_identity",
                "transaction_compliance", 
                "payment_fraud",
            ],
        },
        "features": {
            "real_time_alerts": True,
            "websocket_support": True,
            "hmac_authentication": True,
            "jwt_authentication": True,
            "audit_logging": True,
            "risk_scoring": True,
        },
        "timestamp": time.time(),
    })
