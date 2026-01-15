import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class ValidationError:
    field: str
    code: str
    message: str


@dataclass
class ValidationResult:
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    sanitized_data: Dict[str, Any] = field(default_factory=dict)


class RequestValidator:
    DANGEROUS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"data:text/html",
        r"vbscript:",
        r"\{\{.*\}\}",
        r"\$\{.*\}",
    ]

    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
        r"(--|#|/\*)",
        r"(\bOR\b\s+\d+\s*=\s*\d+)",
        r"(\bAND\b\s+\d+\s*=\s*\d+)",
        r"(;\s*(SELECT|INSERT|UPDATE|DELETE|DROP))",
    ]

    @classmethod
    def sanitize_string(cls, value: str, max_length: int = 1000) -> str:
        if not isinstance(value, str):
            return str(value)

        value = value[:max_length]
        value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

        return value.strip()

    @classmethod
    def check_dangerous_content(cls, value: str) -> Optional[str]:
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return f"Potentially dangerous content detected: {pattern}"

        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return f"Potential SQL injection detected"

        return None

    @classmethod
    def validate_uuid(cls, value: str, field_name: str) -> Optional[ValidationError]:
        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        if not re.match(uuid_pattern, str(value).lower()):
            return ValidationError(
                field=field_name,
                code="invalid_uuid",
                message=f"{field_name} must be a valid UUID",
            )
        return None

    @classmethod
    def validate_email(cls, value: str, field_name: str) -> Optional[ValidationError]:
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, str(value)):
            return ValidationError(
                field=field_name,
                code="invalid_email",
                message=f"{field_name} must be a valid email address",
            )
        return None

    @classmethod
    def validate_amount(
        cls,
        value: Any,
        field_name: str,
        min_value: float = 0,
        max_value: float = 1_000_000_000,
    ) -> Optional[ValidationError]:
        try:
            amount = float(value)
            if amount < min_value or amount > max_value:
                return ValidationError(
                    field=field_name,
                    code="amount_out_of_range",
                    message=f"{field_name} must be between {min_value} and {max_value}",
                )
        except (ValueError, TypeError):
            return ValidationError(
                field=field_name,
                code="invalid_amount",
                message=f"{field_name} must be a valid number",
            )
        return None

    @classmethod
    def validate_currency_code(cls, value: str, field_name: str) -> Optional[ValidationError]:
        if not re.match(r"^[A-Z]{3}$", str(value).upper()):
            return ValidationError(
                field=field_name,
                code="invalid_currency",
                message=f"{field_name} must be a valid 3-letter currency code",
            )
        return None

    @classmethod
    def validate_country_code(cls, value: str, field_name: str) -> Optional[ValidationError]:
        if not re.match(r"^[A-Z]{2}$", str(value).upper()):
            return ValidationError(
                field=field_name,
                code="invalid_country",
                message=f"{field_name} must be a valid 2-letter country code",
            )
        return None

    @classmethod
    def validate_ip_address(cls, value: str, field_name: str) -> Optional[ValidationError]:
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        ipv6_pattern = r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"

        if not (re.match(ipv4_pattern, value) or re.match(ipv6_pattern, value)):
            return ValidationError(
                field=field_name,
                code="invalid_ip",
                message=f"{field_name} must be a valid IP address",
            )
        return None

    @classmethod
    def validate_request_body(
        cls,
        data: Dict[str, Any],
        required_fields: List[str] = None,
        optional_fields: List[str] = None,
    ) -> ValidationResult:
        errors = []
        sanitized = {}

        if required_fields:
            for field_name in required_fields:
                if field_name not in data or data[field_name] is None:
                    errors.append(ValidationError(
                        field=field_name,
                        code="required_field",
                        message=f"{field_name} is required",
                    ))

        all_fields = (required_fields or []) + (optional_fields or [])

        for field_name, value in data.items():
            if all_fields and field_name not in all_fields:
                continue

            if isinstance(value, str):
                sanitized_value = cls.sanitize_string(value)
                danger_check = cls.check_dangerous_content(sanitized_value)
                if danger_check:
                    errors.append(ValidationError(
                        field=field_name,
                        code="dangerous_content",
                        message=danger_check,
                    ))
                sanitized[field_name] = sanitized_value
            elif isinstance(value, dict):
                nested_result = cls.validate_request_body(value)
                if not nested_result.valid:
                    for error in nested_result.errors:
                        error.field = f"{field_name}.{error.field}"
                        errors.append(error)
                sanitized[field_name] = nested_result.sanitized_data
            elif isinstance(value, list):
                sanitized_list = []
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        sanitized_item = cls.sanitize_string(item)
                        danger_check = cls.check_dangerous_content(sanitized_item)
                        if danger_check:
                            errors.append(ValidationError(
                                field=f"{field_name}[{i}]",
                                code="dangerous_content",
                                message=danger_check,
                            ))
                        sanitized_list.append(sanitized_item)
                    else:
                        sanitized_list.append(item)
                sanitized[field_name] = sanitized_list
            else:
                sanitized[field_name] = value

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            sanitized_data=sanitized,
        )
