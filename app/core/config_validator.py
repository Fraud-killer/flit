"""
Configuration Validator for FLIT

Validates all required configuration at startup to fail fast
if the environment is misconfigured.
"""

import os
import sys
from typing import List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ConfigError:
    """Represents a configuration error."""
    variable: str
    message: str
    severity: str = "error"  # error, warning


class ConfigValidator:
    """Validates application configuration at startup."""
    
    # Required environment variables
    REQUIRED_VARS = [
        ("SECRET_KEY", "Django secret key for cryptographic signing"),
        ("MCRYPT_KEY", "Encryption key for sensitive data"),
        ("DATABASE_URL", "Database connection string"),
    ]
    
    # Optional but recommended for production
    RECOMMENDED_VARS = [
        ("REDIS_URL", "Redis URL for caching and channels"),
        ("ALLOWED_HOSTS", "Comma-separated list of allowed hosts"),
        ("FINGERPRINT_API_KEY", "Fingerprint.js API key"),
    ]
    
    # Security-sensitive defaults that should be changed
    INSECURE_DEFAULTS = {
        "SECRET_KEY": ["django-insecure-", "changeme", "secret", "dev"],
        "MCRYPT_KEY": ["changeme", "dev", "test"],
    }
    
    # Minimum lengths for security keys
    MIN_KEY_LENGTHS = {
        "SECRET_KEY": 50,
        "MCRYPT_KEY": 32,
    }
    
    def __init__(self):
        self.errors: List[ConfigError] = []
        self.warnings: List[ConfigError] = []
    
    def validate(self) -> Tuple[bool, List[ConfigError], List[ConfigError]]:
        """
        Validate all configuration.
        
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []
        
        self._check_required_vars()
        self._check_recommended_vars()
        self._check_insecure_defaults()
        self._check_key_lengths()
        self._check_database_config()
        self._check_debug_mode()
        
        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings
    
    def _check_required_vars(self):
        """Check that all required variables are set."""
        for var_name, description in self.REQUIRED_VARS:
            value = os.environ.get(var_name)
            if not value:
                self.errors.append(ConfigError(
                    variable=var_name,
                    message=f"Required: {description}",
                    severity="error"
                ))
    
    def _check_recommended_vars(self):
        """Check recommended variables and warn if missing."""
        debug = os.environ.get("DEBUG", "").lower() in ("true", "1", "yes")
        
        # Only warn about recommended vars in production
        if not debug:
            for var_name, description in self.RECOMMENDED_VARS:
                value = os.environ.get(var_name)
                if not value:
                    self.warnings.append(ConfigError(
                        variable=var_name,
                        message=f"Recommended for production: {description}",
                        severity="warning"
                    ))
    
    def _check_insecure_defaults(self):
        """Check for insecure default values."""
        debug = os.environ.get("DEBUG", "").lower() in ("true", "1", "yes")
        
        for var_name, insecure_patterns in self.INSECURE_DEFAULTS.items():
            value = os.environ.get(var_name, "")
            for pattern in insecure_patterns:
                if pattern.lower() in value.lower():
                    if debug:
                        self.warnings.append(ConfigError(
                            variable=var_name,
                            message=f"Using insecure default value (OK for development)",
                            severity="warning"
                        ))
                    else:
                        self.errors.append(ConfigError(
                            variable=var_name,
                            message=f"Insecure default value detected in production",
                            severity="error"
                        ))
                    break
    
    def _check_key_lengths(self):
        """Check that security keys meet minimum length requirements."""
        for var_name, min_length in self.MIN_KEY_LENGTHS.items():
            value = os.environ.get(var_name, "")
            if value and len(value) < min_length:
                self.warnings.append(ConfigError(
                    variable=var_name,
                    message=f"Key length ({len(value)}) below recommended minimum ({min_length})",
                    severity="warning"
                ))
    
    def _check_database_config(self):
        """Validate database configuration."""
        db_url = os.environ.get("DATABASE_URL", "")
        
        if db_url:
            # Check for SQLite in production
            debug = os.environ.get("DEBUG", "").lower() in ("true", "1", "yes")
            if not debug and "sqlite" in db_url.lower():
                self.warnings.append(ConfigError(
                    variable="DATABASE_URL",
                    message="SQLite detected in production - consider PostgreSQL",
                    severity="warning"
                ))
            
            # Check for SSL in production PostgreSQL
            if not debug and "postgres" in db_url.lower():
                if "sslmode" not in db_url.lower():
                    self.warnings.append(ConfigError(
                        variable="DATABASE_URL",
                        message="PostgreSQL without SSL mode specified",
                        severity="warning"
                    ))
    
    def _check_debug_mode(self):
        """Warn about debug mode in production-like environments."""
        debug = os.environ.get("DEBUG", "").lower() in ("true", "1", "yes")
        allowed_hosts = os.environ.get("ALLOWED_HOSTS", "")
        
        # If ALLOWED_HOSTS is set to production domains but DEBUG is on
        if debug and allowed_hosts:
            production_indicators = [".com", ".io", ".co", ".net", ".org"]
            if any(ind in allowed_hosts for ind in production_indicators):
                self.warnings.append(ConfigError(
                    variable="DEBUG",
                    message="DEBUG=True with production-like ALLOWED_HOSTS",
                    severity="warning"
                ))
    
    def print_report(self):
        """Print a formatted validation report."""
        print("\n" + "=" * 60)
        print("FLIT Configuration Validation Report")
        print("=" * 60)
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"   [{error.variable}] {error.message}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   [{warning.variable}] {warning.message}")
        
        if not self.errors and not self.warnings:
            print("\n✅ All configuration checks passed!")
        
        print("\n" + "=" * 60 + "\n")


def validate_config_or_exit():
    """Validate configuration and exit if invalid."""
    validator = ConfigValidator()
    is_valid, errors, warnings = validator.validate()
    
    if errors or warnings:
        validator.print_report()
    
    if not is_valid:
        print("❌ Configuration validation failed. Please fix the errors above.")
        sys.exit(1)
    
    return True


def get_config_status() -> dict:
    """Get configuration status as a dictionary."""
    validator = ConfigValidator()
    is_valid, errors, warnings = validator.validate()
    
    return {
        "valid": is_valid,
        "errors": [{"variable": e.variable, "message": e.message} for e in errors],
        "warnings": [{"variable": w.variable, "message": w.message} for w in warnings],
    }
