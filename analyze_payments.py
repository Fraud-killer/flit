#!/usr/bin/env python
"""
FLIT Payment Data Analyzer

Analyzes card payment transaction data for fraud patterns using FLIT's
security rules and risk scoring engine.

Usage:
    python analyze_payments.py "card data.json"
"""

import json
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import math


@dataclass
class FraudAlert:
    level: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    message: str
    transaction_id: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    total_transactions: int = 0
    successful: int = 0
    failed: int = 0
    pending: int = 0
    total_amount: float = 0
    successful_amount: float = 0
    failed_amount: float = 0
    alerts: List[FraudAlert] = field(default_factory=list)
    risk_scores: Dict[str, float] = field(default_factory=dict)
    patterns: Dict[str, Any] = field(default_factory=dict)


class PaymentAnalyzer:
    """Analyzes payment transactions for fraud patterns."""

    HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU", "RU", "BY"}
    
    VELOCITY_THRESHOLDS = {
        "per_card_per_hour": 5,
        "per_card_per_day": 20,
        "per_ip_per_hour": 10,
        "per_customer_per_hour": 5,
    }

    HIGH_VALUE_THRESHOLD = 10000  # USD cents
    RAPID_RETRY_SECONDS = 300  # 5 minutes

    def __init__(self):
        self.result = AnalysisResult()
        self.transactions_by_card: Dict[str, List[dict]] = defaultdict(list)
        self.transactions_by_ip: Dict[str, List[dict]] = defaultdict(list)
        self.transactions_by_customer: Dict[str, List[dict]] = defaultdict(list)
        self.failed_cards: Set[str] = set()
        self.card_locations: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)

    def load_data(self, filepath: str) -> List[dict]:
        """Load and parse payment data from JSON file."""
        with open(filepath, 'r') as f:
            content = f.read()
            
        # Fix common JSON issues
        if content.startswith("can["):
            content = content[3:]
        if content.endswith("]."):
            content = content[:-1]
            
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            # Try to fix and parse
            content = content.strip()
            if not content.startswith("["):
                content = "[" + content
            if not content.endswith("]"):
                content = content + "]"
            data = json.loads(content)
            
        return data

    def parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse ISO timestamp string."""
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except:
            return None

    def parse_nested_json(self, value: str) -> dict:
        """Parse nested JSON string fields."""
        if isinstance(value, dict):
            return value
        if not value or not isinstance(value, str):
            return {}
        try:
            return json.loads(value)
        except:
            return {}

    def extract_card_number(self, payment_instrument: dict) -> str:
        """Extract masked card number."""
        card = payment_instrument.get("card", {})
        return card.get("number", "UNKNOWN")

    def extract_ip(self, request_details: dict) -> str:
        """Extract IP address from request details."""
        return request_details.get("ipAddress", "UNKNOWN")

    def extract_city(self, billing: dict) -> str:
        """Extract city from billing address."""
        return billing.get("city", "UNKNOWN")

    def haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km."""
        R = 6371  # Earth's radius in km
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        
        return R * c

    def analyze_transaction(self, tx: dict) -> List[FraudAlert]:
        """Analyze a single transaction for fraud indicators."""
        alerts = []
        tx_id = tx.get("ID", "UNKNOWN")
        amount = tx.get("Amount", 0)
        status = tx.get("Status", "unknown")
        customer_id = tx.get("Customer ID", "UNKNOWN")
        gateway_message = tx.get("Gateway Message", "")
        
        # Parse nested fields
        payment_instrument = self.parse_nested_json(tx.get("Payment Instrument", "{}"))
        request_details = self.parse_nested_json(tx.get("Request Details", "{}"))
        billing = self.parse_nested_json(tx.get("Billing", "{}"))
        shipping = self.parse_nested_json(tx.get("Shipping", "{}"))
        
        card_number = self.extract_card_number(payment_instrument)
        ip_address = self.extract_ip(request_details)
        created_at = self.parse_timestamp(tx.get("Created At"))
        
        # Update statistics
        self.result.total_transactions += 1
        self.result.total_amount += amount
        
        if status == "success":
            self.result.successful += 1
            self.result.successful_amount += amount
        elif status == "failed":
            self.result.failed += 1
            self.result.failed_amount += amount
            self.failed_cards.add(card_number)
        else:
            self.result.pending += 1

        # Index transactions
        if created_at:
            self.transactions_by_card[card_number].append({"tx": tx, "time": created_at})
            self.transactions_by_ip[ip_address].append({"tx": tx, "time": created_at})
            self.transactions_by_customer[customer_id].append({"tx": tx, "time": created_at})
            
            city = self.extract_city(billing)
            self.card_locations[card_number].append((city, created_at))

        # Rule 1: High value transaction
        if amount >= self.HIGH_VALUE_THRESHOLD:
            alerts.append(FraudAlert(
                level="MEDIUM",
                category="high_value",
                message=f"High value transaction: ${amount/100:.2f}",
                transaction_id=tx_id,
                details={"amount": amount, "threshold": self.HIGH_VALUE_THRESHOLD}
            ))

        # Rule 2: Anti-fraud decline
        if "anti-fraud" in gateway_message.lower():
            alerts.append(FraudAlert(
                level="HIGH",
                category="issuer_fraud_flag",
                message=f"Issuer anti-fraud system triggered: {gateway_message}",
                transaction_id=tx_id,
                details={"gateway_message": gateway_message}
            ))

        # Rule 3: Business rules decline (often velocity)
        if "business rules" in gateway_message.lower():
            alerts.append(FraudAlert(
                level="MEDIUM",
                category="business_rules",
                message=f"Business rules triggered: {gateway_message}",
                transaction_id=tx_id,
                details={"gateway_message": gateway_message}
            ))

        # Rule 4: Suspicious billing address
        if billing.get("city") == "NA" or billing.get("address1") == "NA":
            alerts.append(FraudAlert(
                level="MEDIUM",
                category="incomplete_billing",
                message="Incomplete or placeholder billing address",
                transaction_id=tx_id,
                details={"billing": billing}
            ))

        # Rule 5: Billing/Shipping mismatch
        if billing.get("city") and shipping.get("city"):
            if billing.get("city") != shipping.get("city"):
                alerts.append(FraudAlert(
                    level="LOW",
                    category="address_mismatch",
                    message=f"Billing city ({billing.get('city')}) differs from shipping ({shipping.get('city')})",
                    transaction_id=tx_id,
                    details={"billing_city": billing.get("city"), "shipping_city": shipping.get("city")}
                ))

        # Rule 6: Bot/automation indicators
        browser_details = request_details.get("browserDetails", {})
        if browser_details.get("userAgent", "").startswith("Faraday"):
            alerts.append(FraudAlert(
                level="HIGH",
                category="automation_detected",
                message="Automated HTTP client detected (Faraday)",
                transaction_id=tx_id,
                details={"user_agent": browser_details.get("userAgent")}
            ))

        # Rule 7: Suspicious screen dimensions (headless browser indicators)
        if browser_details.get("screenWidth") == 480 and browser_details.get("screenHeight") == 640:
            alerts.append(FraudAlert(
                level="MEDIUM",
                category="suspicious_browser",
                message="Suspicious screen dimensions (possible headless browser)",
                transaction_id=tx_id,
                details={"screen": f"{browser_details.get('screenWidth')}x{browser_details.get('screenHeight')}"}
            ))

        # Rule 8: JavaScript disabled
        if browser_details.get("javascriptEnabled") == False:
            alerts.append(FraudAlert(
                level="LOW",
                category="js_disabled",
                message="JavaScript disabled (unusual for legitimate users)",
                transaction_id=tx_id,
                details={}
            ))

        return alerts

    def analyze_patterns(self) -> List[FraudAlert]:
        """Analyze cross-transaction patterns."""
        alerts = []

        # Pattern 1: Velocity by card
        for card, txs in self.transactions_by_card.items():
            if len(txs) < 2:
                continue
                
            txs_sorted = sorted(txs, key=lambda x: x["time"])
            
            # Check hourly velocity
            for i, tx_data in enumerate(txs_sorted):
                hour_window = [t for t in txs_sorted if 
                              0 <= (tx_data["time"] - t["time"]).total_seconds() <= 3600]
                if len(hour_window) > self.VELOCITY_THRESHOLDS["per_card_per_hour"]:
                    alerts.append(FraudAlert(
                        level="HIGH",
                        category="velocity_card",
                        message=f"Card {card} used {len(hour_window)} times in 1 hour",
                        transaction_id=tx_data["tx"].get("ID"),
                        details={"card": card, "count": len(hour_window)}
                    ))
                    break

            # Check rapid retries after failure
            for i in range(1, len(txs_sorted)):
                prev = txs_sorted[i-1]
                curr = txs_sorted[i]
                time_diff = (curr["time"] - prev["time"]).total_seconds()
                
                if time_diff < self.RAPID_RETRY_SECONDS:
                    if prev["tx"].get("Status") == "failed":
                        alerts.append(FraudAlert(
                            level="MEDIUM",
                            category="rapid_retry",
                            message=f"Rapid retry after failure: {time_diff:.0f}s between attempts",
                            transaction_id=curr["tx"].get("ID"),
                            details={"card": card, "seconds": time_diff}
                        ))

        # Pattern 2: Same card, different locations (impossible travel)
        for card, locations in self.card_locations.items():
            if len(locations) < 2:
                continue
                
            locations_sorted = sorted(locations, key=lambda x: x[1])
            for i in range(1, len(locations_sorted)):
                prev_city, prev_time = locations_sorted[i-1]
                curr_city, curr_time = locations_sorted[i]
                
                if prev_city != curr_city and prev_city != "NA" and curr_city != "NA":
                    time_diff_hours = (curr_time - prev_time).total_seconds() / 3600
                    if time_diff_hours < 2:  # Less than 2 hours between different cities
                        alerts.append(FraudAlert(
                            level="HIGH",
                            category="impossible_travel",
                            message=f"Card used in {prev_city} then {curr_city} within {time_diff_hours:.1f} hours",
                            transaction_id="PATTERN",
                            details={"card": card, "cities": [prev_city, curr_city], "hours": time_diff_hours}
                        ))

        # Pattern 3: IP velocity
        for ip, txs in self.transactions_by_ip.items():
            if len(txs) > self.VELOCITY_THRESHOLDS["per_ip_per_hour"]:
                # Check if within 1 hour
                times = [t["time"] for t in txs]
                times_sorted = sorted(times)
                if (times_sorted[-1] - times_sorted[0]).total_seconds() <= 3600:
                    alerts.append(FraudAlert(
                        level="HIGH",
                        category="velocity_ip",
                        message=f"IP {ip} used for {len(txs)} transactions in 1 hour",
                        transaction_id="PATTERN",
                        details={"ip": ip, "count": len(txs)}
                    ))

        # Pattern 4: Card testing (multiple small amounts)
        for card, txs in self.transactions_by_card.items():
            small_txs = [t for t in txs if t["tx"].get("Amount", 0) < 500]  # Under $5
            if len(small_txs) >= 3:
                alerts.append(FraudAlert(
                    level="HIGH",
                    category="card_testing",
                    message=f"Possible card testing: {len(small_txs)} small transactions on {card}",
                    transaction_id="PATTERN",
                    details={"card": card, "small_tx_count": len(small_txs)}
                ))

        # Pattern 5: High failure rate per card
        for card, txs in self.transactions_by_card.items():
            if len(txs) >= 3:
                failed = sum(1 for t in txs if t["tx"].get("Status") == "failed")
                failure_rate = failed / len(txs)
                if failure_rate >= 0.7:
                    alerts.append(FraudAlert(
                        level="MEDIUM",
                        category="high_failure_rate",
                        message=f"Card {card} has {failure_rate*100:.0f}% failure rate ({failed}/{len(txs)})",
                        transaction_id="PATTERN",
                        details={"card": card, "failure_rate": failure_rate}
                    ))

        return alerts

    def calculate_risk_score(self, alerts: List[FraudAlert]) -> float:
        """Calculate overall risk score from alerts."""
        if not alerts:
            return 0.0
            
        weights = {
            "CRITICAL": 1.0,
            "HIGH": 0.7,
            "MEDIUM": 0.4,
            "LOW": 0.2,
        }
        
        total_weight = sum(weights.get(a.level, 0.3) for a in alerts)
        return min(total_weight / 5, 1.0)  # Normalize to 0-1

    def analyze(self, filepath: str) -> AnalysisResult:
        """Run full analysis on payment data."""
        print(f"\n{'='*60}")
        print("FLIT PAYMENT DATA ANALYSIS")
        print(f"{'='*60}\n")
        
        # Load data
        print(f"Loading data from: {filepath}")
        transactions = self.load_data(filepath)
        print(f"Loaded {len(transactions)} transactions\n")

        # Analyze each transaction
        print("Analyzing individual transactions...")
        for tx in transactions:
            alerts = self.analyze_transaction(tx)
            self.result.alerts.extend(alerts)

        # Analyze patterns
        print("Analyzing cross-transaction patterns...")
        pattern_alerts = self.analyze_patterns()
        self.result.alerts.extend(pattern_alerts)

        # Calculate risk scores
        self.result.risk_scores["overall"] = self.calculate_risk_score(self.result.alerts)

        # Compile patterns
        self.result.patterns = {
            "unique_cards": len(self.transactions_by_card),
            "unique_ips": len(self.transactions_by_ip),
            "unique_customers": len(self.transactions_by_customer),
            "failed_cards": len(self.failed_cards),
        }

        return self.result

    def print_report(self):
        """Print analysis report."""
        r = self.result
        
        print(f"\n{'='*60}")
        print("TRANSACTION SUMMARY")
        print(f"{'='*60}")
        print(f"Total Transactions:    {r.total_transactions}")
        print(f"  Successful:          {r.successful} ({r.successful/r.total_transactions*100:.1f}%)")
        print(f"  Failed:              {r.failed} ({r.failed/r.total_transactions*100:.1f}%)")
        print(f"  Pending:             {r.pending} ({r.pending/r.total_transactions*100:.1f}%)")
        print(f"\nTotal Amount:          ${r.total_amount/100:,.2f}")
        print(f"  Successful:          ${r.successful_amount/100:,.2f}")
        print(f"  Failed:              ${r.failed_amount/100:,.2f}")

        print(f"\n{'='*60}")
        print("ENTITY ANALYSIS")
        print(f"{'='*60}")
        print(f"Unique Cards:          {r.patterns['unique_cards']}")
        print(f"Unique IPs:            {r.patterns['unique_ips']}")
        print(f"Unique Customers:      {r.patterns['unique_customers']}")
        print(f"Cards with Failures:   {r.patterns['failed_cards']}")

        print(f"\n{'='*60}")
        print("RISK ASSESSMENT")
        print(f"{'='*60}")
        risk_score = r.risk_scores.get("overall", 0)
        risk_level = "LOW" if risk_score < 0.3 else "MEDIUM" if risk_score < 0.5 else "HIGH" if risk_score < 0.7 else "CRITICAL"
        print(f"Overall Risk Score:    {risk_score:.2f}")
        print(f"Risk Level:            {risk_level}")

        # Alert summary by category
        print(f"\n{'='*60}")
        print("FRAUD ALERTS SUMMARY")
        print(f"{'='*60}")
        
        alerts_by_level = defaultdict(list)
        alerts_by_category = defaultdict(list)
        
        for alert in r.alerts:
            alerts_by_level[alert.level].append(alert)
            alerts_by_category[alert.category].append(alert)

        print(f"\nBy Severity:")
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len(alerts_by_level.get(level, []))
            if count > 0:
                print(f"  {level}: {count}")

        print(f"\nBy Category:")
        for category, alerts in sorted(alerts_by_category.items(), key=lambda x: -len(x[1])):
            print(f"  {category}: {len(alerts)}")

        # Top alerts
        print(f"\n{'='*60}")
        print("TOP CRITICAL/HIGH ALERTS (First 20)")
        print(f"{'='*60}")
        
        high_alerts = [a for a in r.alerts if a.level in ["CRITICAL", "HIGH"]][:20]
        for i, alert in enumerate(high_alerts, 1):
            print(f"\n{i}. [{alert.level}] {alert.category}")
            print(f"   {alert.message}")
            if alert.transaction_id != "PATTERN":
                print(f"   Transaction: {alert.transaction_id[:8]}...")

        # Recommendations
        print(f"\n{'='*60}")
        print("RECOMMENDATIONS")
        print(f"{'='*60}")
        
        if len(alerts_by_category.get("automation_detected", [])) > 0:
            print("\n⚠️  CRITICAL: Automated/bot traffic detected")
            print("   - All transactions appear to use Faraday HTTP client")
            print("   - This indicates programmatic access, not real users")
            print("   - Recommend: Block this traffic or require CAPTCHA")

        if len(alerts_by_category.get("velocity_card", [])) > 0:
            print("\n⚠️  HIGH: Card velocity violations detected")
            print("   - Multiple cards used excessively in short time windows")
            print("   - Recommend: Implement stricter rate limiting per card")

        if len(alerts_by_category.get("velocity_ip", [])) > 0:
            print("\n⚠️  HIGH: IP velocity violations detected")
            print("   - Same IPs used for many transactions")
            print("   - Recommend: Implement IP-based rate limiting")

        if len(alerts_by_category.get("issuer_fraud_flag", [])) > 0:
            print("\n⚠️  HIGH: Issuer anti-fraud triggers")
            print("   - Card issuers are flagging transactions as fraudulent")
            print("   - Recommend: Review these customers/cards carefully")

        if r.failed / r.total_transactions > 0.5:
            print("\n⚠️  MEDIUM: High overall failure rate")
            print(f"   - {r.failed/r.total_transactions*100:.1f}% of transactions failed")
            print("   - This may indicate card testing or fraud attempts")

        print(f"\n{'='*60}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*60}\n")


def main():
    if len(sys.argv) < 2:
        filepath = "/Users/abrahamojes/CascadeProjects/windsurf-project-9/flit/card data.json"
    else:
        filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    analyzer = PaymentAnalyzer()
    analyzer.analyze(filepath)
    analyzer.print_report()


if __name__ == "__main__":
    main()
