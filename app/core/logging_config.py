"""
Structured Logging Configuration for FLIT

Provides JSON-formatted logging with correlation IDs,
request context, and proper log levels for production.
"""

import logging
import json
import uuid
from datetime import datetime
from typing import Any, Dict, Optional
from contextvars import ContextVar
from functools import wraps

# Context variable for request correlation
request_id_var: ContextVar[str] = ContextVar("request_id", default="")
application_id_var: ContextVar[str] = ContextVar("application_id", default="")


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add correlation context
        request_id = request_id_var.get()
        if request_id:
            log_data["request_id"] = request_id
        
        application_id = application_id_var.get()
        if application_id:
            log_data["application_id"] = application_id
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data["data"] = record.extra_data
        
        return json.dumps(log_data)


class FlitLogger:
    """Enhanced logger with structured logging support."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def _log(
        self,
        level: int,
        message: str,
        extra_data: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Internal log method with extra data support."""
        extra = kwargs.get("extra", {})
        if extra_data:
            extra["extra_data"] = extra_data
        kwargs["extra"] = extra
        self.logger.log(level, message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, **kwargs)
    
    def audit(
        self,
        action: str,
        actor_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        risk_score: Optional[float] = None,
        outcome: Optional[str] = None,
        **extra
    ):
        """Log an audit event with structured data."""
        self._log(
            logging.INFO,
            f"AUDIT: {action}",
            extra_data={
                "audit": True,
                "action": action,
                "actor_id": actor_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "risk_score": risk_score,
                "outcome": outcome,
                **extra,
            }
        )
    
    def fraud_alert(
        self,
        alert_type: str,
        risk_score: float,
        factors: list,
        transaction_id: Optional[str] = None,
        **extra
    ):
        """Log a fraud alert with structured data."""
        level = logging.CRITICAL if risk_score >= 0.85 else logging.WARNING
        self._log(
            level,
            f"FRAUD_ALERT: {alert_type}",
            extra_data={
                "fraud_alert": True,
                "alert_type": alert_type,
                "risk_score": risk_score,
                "factors": factors,
                "transaction_id": transaction_id,
                **extra,
            }
        )


def get_logger(name: str) -> FlitLogger:
    """Get a FLIT logger instance."""
    return FlitLogger(name)


def set_request_context(request_id: str, application_id: str = ""):
    """Set the request context for logging."""
    request_id_var.set(request_id)
    application_id_var.set(application_id)


def generate_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())


def configure_logging(debug: bool = False):
    """Configure logging for the application."""
    log_level = logging.DEBUG if debug else logging.INFO
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler with JSON formatting
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(console_handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger("django").setLevel(logging.WARNING)
    logging.getLogger("channels").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


# Logging configuration dictionary for Django settings
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": JSONFormatter,
        },
        "simple": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "flit": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "flit.audit": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "flit.fraud": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
