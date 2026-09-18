"""
Generate a synthetic export to exercise the backtest harness.

Not a substitute for real data: the patterns are planted, so FLIT finding
them proves the harness runs end to end, not that the rules are accurate.
Real accuracy numbers need real portfolios.

    python manage.py backtest_sample --out wallet.csv --mapping wallet_mapping.json
"""

import csv
import json
import random
from datetime import datetime, timedelta, timezone as datetime_timezone

from django.core.management.base import BaseCommand


COLUMNS = [
    "txn_ref", "direction", "amount_minor", "customer_uuid", "peer_uuid",
    "device_hash", "ip", "user_agent", "created_at", "outcome", "customer_age_days",
]

MAPPING = {
    "fields": {
        "id": "txn_ref",
        "type": "direction",
        "amount": "amount_minor",
        "client_id": "customer_uuid",
        "counterparty_id": "peer_uuid",
        "device_id": "device_hash",
        "ip_address": "ip",
        "user_agent": "user_agent",
        "account_age_days": "customer_age_days",
    },
    "constants": {"currency_code": "NGN"},
    "values": {"type": {"IN": "credit", "OUT": "debit"}},
    "label_field": "outcome",
    "labels": {"chargeback": "chargeback", "fraud": "fraud", "settled": "legit"},
    "amount_scale": 0.01,
    "timestamp_field": "created_at",
}

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) Chrome/119.0",
]


class Command(BaseCommand):
    help = "Write a synthetic payments export and its mapping file"

    def add_arguments(self, parser):
        parser.add_argument("--out", required=True, help="Where to write the CSV")
        parser.add_argument("--mapping", help="Where to write the mapping JSON")
        parser.add_argument("--customers", type=int, default=120)
        parser.add_argument("--days", type=int, default=45)
        parser.add_argument("--seed", type=int, default=7)
        parser.add_argument("--prefix", default="p1",
                            help="Namespace for this portfolio's customers, devices and IPs")
        parser.add_argument("--shared-ring", action="store_true",
                            help="Reuse the mule ring's devices and herders across portfolios, "
                                 "so an overlap analysis has something real to find")

    def handle(self, *args, **options):
        random.seed(options["seed"])

        self.prefix = options["prefix"]
        self.shared_ring = options["shared_ring"]

        start = datetime.now(datetime_timezone.utc) - timedelta(days=options["days"])
        rows = []

        rows += self.ordinary_customers(start, options["customers"], options["days"])
        rows += self.mule_ring(start, options["days"])
        rows += self.card_testers(start, options["days"])

        rows.sort(key=lambda row: row["created_at"])

        with open(options["out"], "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

        if options["mapping"]:
            with open(options["mapping"], "w") as handle:
                json.dump(MAPPING, handle, indent=2)

        fraud = sum(1 for row in rows if row["outcome"] in ("fraud", "chargeback"))
        self.stdout.write(
            f"Wrote {len(rows)} transactions ({fraud} fraudulent) to {options['out']}"
        )

    def ordinary_customers(self, start, count, days):
        """Salary in, spending out, from a stable device."""
        rows = []

        for customer in range(count):
            customer_id = f"{self.prefix}_cust_{customer:04d}"
            device = f"{self.prefix}_dev_{customer:04d}"
            browser = random.choice(BROWSERS)
            ip = f"102.89.{customer % 250}.{random.randint(2, 250)}"
            age = random.randint(120, 1500)

            for day in range(0, days, random.randint(5, 12)):
                moment = start + timedelta(days=day, hours=random.randint(8, 20))

                rows.append(self.row(
                    f"{customer_id}_in_{day}", "IN", random.randint(40000, 350000),
                    customer_id, f"{self.prefix}_payroll", device, ip, browser, moment, "settled", age,
                ))

                for spend in range(random.randint(1, 3)):
                    rows.append(self.row(
                        f"{customer_id}_out_{day}_{spend}", "OUT", random.randint(2000, 30000),
                        customer_id, f"{self.prefix}_merchant_{random.randint(1, 40)}", device, ip, browser,
                        moment + timedelta(hours=random.randint(4, 40)), "settled", age,
                    ))

        return rows

    def mule_ring(self, start, days):
        """Fresh accounts on shared devices: victims pay in, funds leave at once."""
        rows = []

        for ring in range(3):
            # A ring working both portfolios is what a consortium would catch.
            ring_name = f"ring_{ring}" if self.shared_ring else f"{self.prefix}_ring_{ring}"
            device = f"dev_mule_{ring_name}"
            ip = f"197.210.{ring}.{random.randint(2, 200)}"

            for mule in range(4):
                mule_id = f"{self.prefix}_mule_{ring}_{mule}"
                opened = start + timedelta(days=random.randint(1, days - 3))

                received = 0
                for victim in range(random.randint(5, 8)):
                    amount = random.randint(15000, 90000)
                    received += amount
                    rows.append(self.row(
                        f"{mule_id}_in_{victim}", "IN", amount, mule_id, f"{self.prefix}_victim_{ring}_{victim}",
                        device, ip, random.choice(BROWSERS),
                        opened + timedelta(minutes=victim * 7), "settled", random.randint(0, 6),
                    ))

                rows.append(self.row(
                    f"{mule_id}_out", "OUT", int(received * 0.95), mule_id, f"herder_{ring_name}",
                    device, ip, random.choice(BROWSERS),
                    opened + timedelta(minutes=55), "fraud", random.randint(0, 6),
                ))

        return rows

    def card_testers(self, start, days):
        """Automated clients running small payments from one datacenter IP."""
        rows = []
        ip = "54.217.46.204"

        for attempt in range(40):
            moment = start + timedelta(days=random.randint(1, days), seconds=attempt * 90)
            customer_id = f"{self.prefix}_tester_{attempt % 6}"

            rows.append(self.row(
                f"{self.prefix}_test_{attempt}", "OUT", random.randint(100, 900), customer_id,
                f"{self.prefix}_merchant_{random.randint(1, 5)}", f"dev_bot_{attempt % 3}", ip,
                "curl/8.0", moment, "chargeback" if attempt % 3 == 0 else "settled", 1,
            ))

        return rows

    def row(self, reference, direction, amount, customer, peer, device, ip, agent, moment, outcome, age):
        return dict(
            txn_ref=reference,
            direction=direction,
            amount_minor=amount,
            customer_uuid=customer,
            peer_uuid=peer,
            device_hash=device,
            ip=ip,
            user_agent=agent,
            created_at=moment.isoformat(),
            outcome=outcome,
            customer_age_days=age,
        )
