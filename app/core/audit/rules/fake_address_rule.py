"""
Fake Address Detection Rule

Detects known fake/test addresses commonly used in fraud attempts.
These include placeholder addresses, test data patterns, and
geographically impossible combinations.
"""

from typing import Any
from .base_rule import BaseRule


class FakeAddressRule(BaseRule):
    """
    Detects fake or suspicious addresses in billing/shipping data.
    
    Common patterns:
    - Known test addresses (Pleasantville, 90210, etc.)
    - Placeholder text (N/A, Test, XXXX)
    - Address1 == Address2 (copy-paste)
    - Generic zip codes (12345, 00000)
    - Country/city mismatches
    """
    
    name = "Fake Address Detection"
    weight = 0.7
    
    # Known fake/test patterns
    FAKE_CITIES = {
        "pleasantville", "testville", "faketown", "nowhere",
        "anytown", "springfield", "gotham", "metropolis",
    }
    
    FAKE_STREETS = {
        "second street 23", "123 main st", "test street",
        "fake address", "no address", "n/a", "none",
        "xxx", "test", "asdf", "qwerty",
    }
    
    FAKE_ZIP_CODES = {
        "12345", "00000", "11111", "99999", "90210",
        "1111", "0000", "123", "000",
    }
    
    PLACEHOLDER_PATTERNS = [
        "test", "fake", "n/a", "none", "xxx", "null",
        "undefined", "placeholder", "sample", "demo",
    ]
    
    async def apply(self, event: dict[str, Any], policy: dict[str, Any]) -> None:
        """Check for fake address patterns."""
        
        billing = event.get("billing", {})
        shipping = event.get("shipping", {})
        
        # Check both billing and shipping addresses
        billing_issues = self._check_address(billing, "billing")
        shipping_issues = self._check_address(shipping, "shipping")
        
        # Check for billing/shipping mismatch (can be legitimate but worth noting)
        if billing and shipping:
            self._check_address_mismatch(billing, shipping)
        
        # Check for address1 == address2 pattern (lazy fraud)
        self._check_duplicate_lines(billing, "billing")
        self._check_duplicate_lines(shipping, "shipping")
        
        # Check for country/city geographic inconsistency
        self._check_geographic_consistency(billing, "billing")
        self._check_geographic_consistency(shipping, "shipping")
    
    def _check_address(self, address: dict, address_type: str) -> list[str]:
        """Check a single address for fake patterns."""
        issues = []
        
        if not address or not isinstance(address, dict):
            return issues
        
        city = str(address.get("city", "")).lower().strip()
        address1 = str(address.get("address1", "")).lower().strip()
        address2 = str(address.get("address2", "")).lower().strip()
        zip_code = str(address.get("zip_code", "")).strip()
        
        # Check for known fake cities
        if city in self.FAKE_CITIES:
            self.add_message(
                f"Known fake city in {address_type}: '{city}'",
                severity="high"
            )
            issues.append("fake_city")
        
        # Check for known fake streets
        for fake_street in self.FAKE_STREETS:
            if fake_street in address1 or fake_street in address2:
                self.add_message(
                    f"Known fake street pattern in {address_type}",
                    severity="high"
                )
                issues.append("fake_street")
                break
        
        # Check for fake zip codes
        if zip_code in self.FAKE_ZIP_CODES:
            self.add_message(
                f"Known test zip code in {address_type}: '{zip_code}'",
                severity="medium"
            )
            issues.append("fake_zip")
        
        # Check for placeholder patterns
        all_fields = f"{city} {address1} {address2}".lower()
        for pattern in self.PLACEHOLDER_PATTERNS:
            if pattern in all_fields and len(pattern) > 2:
                self.add_message(
                    f"Placeholder text detected in {address_type}: '{pattern}'",
                    severity="medium"
                )
                issues.append("placeholder")
                break
        
        return issues
    
    def _check_duplicate_lines(self, address: dict, address_type: str) -> None:
        """Check if address1 == address2 (lazy copy-paste fraud)."""
        if not address or not isinstance(address, dict):
            return
        
        address1 = str(address.get("address1", "")).strip()
        address2 = str(address.get("address2", "")).strip()
        
        if address1 and address2 and address1 == address2:
            self.add_message(
                f"Duplicate address lines in {address_type} (address1 == address2)",
                severity="low"
            )
    
    def _check_address_mismatch(self, billing: dict, shipping: dict) -> None:
        """Check for significant billing/shipping mismatches."""
        if not billing or not shipping:
            return
        
        billing_country = str(billing.get("country", "")).upper()
        shipping_country = str(shipping.get("country", "")).upper()
        
        # Different countries is suspicious for card-not-present
        if billing_country and shipping_country and billing_country != shipping_country:
            self.add_message(
                f"Billing country ({billing_country}) differs from "
                f"shipping country ({shipping_country})",
                severity="medium"
            )
    
    def _check_geographic_consistency(self, address: dict, address_type: str) -> None:
        """Check if city/country combination is geographically possible."""
        if not address or not isinstance(address, dict):
            return
        
        city = str(address.get("city", "")).lower().strip()
        country = str(address.get("country", "")).upper().strip()
        
        # Known impossible combinations from the data
        impossible_combinations = [
            # US cities with non-US countries
            ("pleasantville", "TR"),
            ("springfield", "JP"),
            # Japanese cities with Turkish country
            ("tokyo", "TR"),
            ("osaka", "TR"),
        ]
        
        for fake_city, wrong_country in impossible_combinations:
            if fake_city in city and country == wrong_country:
                self.add_message(
                    f"Geographic impossibility: '{city}' is not in {country}",
                    severity="high"
                )
                return
        
        # Check for Japanese characters with non-JP country
        if any('\u3040' <= c <= '\u30ff' or '\u4e00' <= c <= '\u9fff' for c in city):
            if country and country != "JP":
                self.add_message(
                    f"Japanese address with non-Japanese country code: {country}",
                    severity="medium"
                )
