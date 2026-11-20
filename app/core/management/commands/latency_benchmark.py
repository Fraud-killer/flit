"""
How long a decision takes, measured rather than assumed.

Runs a synthetic mix of signups, logins, password resets, credits and debits
through the engine in a throwaway database, and reports p50 / p95 / p99 end to
end, per stage and per rule. It never touches the configured database: it
creates the test database Django would create for the suite, and drops it
afterwards.

What it measures is the engine as the API view calls it (async_to_sync around
Auditor.audit, one call per worker thread), including the write that records
the decision. It does not measure the HTTP layer in front of it: TLS, request
signing, middleware and serialisation. Add those from a load test (tests/load)
before quoting a number to a customer.

The stage and rule breakdown comes from the spans the auditor records on each
decision. A build without them still reports end-to-end figures.

    python manage.py latency_benchmark
    python manage.py latency_benchmark --events 5000 --concurrency 8 --money-out
    python manage.py latency_benchmark --json ../latency.json

Run it against the same kind of database and cache as production. SQLite and
an in-process cache flatter the numbers.
"""

import importlib.util
import json
import os
import platform
import queue
import random
import statistics
import threading
import time
import uuid
from collections import defaultdict

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, connections


USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
)
EMAIL_DOMAINS = ("gmail.com", "yahoo.com", "outlook.com", "icloud.com")

# The share of each kind of event in the mix: what a payments product's
# traffic roughly looks like, money movement first.
MIX = (
    ("debit", 0.35),
    ("credit", 0.25),
    ("login", 0.20),
    ("registration", 0.08),
    ("password_reset_requested", 0.07),
    ("password_reset_completed", 0.05),
)

# Limits large enough never to trip: this measures the cost of the check,
# not what a trip does.
MONEY_OUT_POLICY = dict(
    outflow_limits={
        "currency": "USD",
        "per_initiator": {"15m": 10**9, "1h": 10**9, "24h": 10**10},
        "per_initiator_untrusted": {"1h": 10**9, "24h": 10**10},
        "per_channel": {"1h": 10**10},
        "per_application": {"24h": 10**11},
        "fail": "block",
    },
    beneficiary_control={"enabled": True, "cooling_hours": 72, "fail": "block"},
)


def percentiles(values):
    """p50, p95, p99 and max, in milliseconds, or None for an empty sample."""
    if not values:
        return None
    if len(values) == 1:
        only = round(values[0], 2)
        return dict(n=1, p50=only, p95=only, p99=only, max=only)
    cuts = statistics.quantiles(values, n=100, method="inclusive")
    return dict(
        n=len(values),
        p50=round(cuts[49], 2),
        p95=round(cuts[94], 2),
        p99=round(cuts[98], 2),
        max=round(max(values), 2),
    )


class Traffic:
    """A deterministic stream of plausible events over a fixed population."""

    def __init__(self, *, seed, accounts, origins, money_out):
        self.random = random.Random(seed)
        self.money_out = money_out
        self.accounts = [f"acct_{n:05d}" for n in range(accounts)]
        # Public-looking addresses spread over a few networks, so IP rules
        # have something to count and nothing is a reserved range.
        self.origins = [
            f"{self.random.choice((102, 105, 41, 197))}.{self.random.randint(1, 254)}."
            f"{self.random.randint(0, 254)}.{self.random.randint(1, 254)}"
            for _ in range(origins)
        ]
        self.home = {account: self.random.choice(self.origins) for account in self.accounts}
        self.counter = 0

    def _kind(self):
        roll, total = self.random.random(), 0.0
        for kind, share in MIX:
            total += share
            if roll < total:
                return kind
        return MIX[-1][0]

    def _origin(self, account):
        # Most events come from the account's usual address.
        return self.home[account] if self.random.random() < 0.85 else self.random.choice(self.origins)

    def next(self):
        from core.audit.events import AuthenticationEvent, RegistrationEvent, TransactionEvent

        self.counter += 1
        kind = self._kind()
        user_agent = self.random.choice(USER_AGENTS)

        if kind == "registration":
            account = f"new_{self.counter:06d}"
            self.accounts.append(account)
            self.home[account] = self.random.choice(self.origins)
            return kind, RegistrationEvent(
                id=account, client_id=account, action="registration", country="NG",
                email=f"user{self.counter}@{self.random.choice(EMAIL_DOMAINS)}",
                ip_address=self.home[account], user_agent=user_agent,
            )

        account = self.random.choice(self.accounts)

        if kind in ("debit", "credit"):
            fields = dict(
                id=f"txn_{self.counter:07d}", type=kind, client_id=account,
                amount=round(self.random.lognormvariate(4.5, 1.2), 2), currency_code="USD",
                ip_address=self._origin(account), user_agent=user_agent,
                counterparty_id=f"cp_{self.random.randint(0, 400):04d}",
                account_age_days=self.random.randint(1, 900),
            )
            if self.money_out and kind == "debit":
                fields.update(
                    initiator_id=self.random.choice(("customer", "customer", "partner_1", "partner_2")),
                    channel=self.random.choice(("nip", "intrabank")),
                    counterparty_bank=self.random.choice(("058", "044", "033", "011")),
                )
            return kind, TransactionEvent(**fields)

        return kind, AuthenticationEvent(
            id=f"auth_{self.counter:07d}", client_id=account, action=kind,
            ip_address=self._origin(account), user_agent=user_agent,
            auth_method="password",
        )


class Command(BaseCommand):
    help = "Measure decision latency (p50/p95/p99, per stage and per rule) on synthetic traffic."

    def add_arguments(self, parser):
        parser.add_argument("--events", type=int, default=1000, help="measured events (default 1000)")
        parser.add_argument("--warmup", type=int, default=100,
                            help="events run first and not measured, so history-reading rules have history")
        parser.add_argument("--history-days", type=float, default=7.0,
                            help="spread the warm-up history evenly over this many past days, as real "
                                 "traffic would be (default 7). 0 leaves it in the last few minutes: "
                                 "every origin's hour is then full, a stress test rather than a forecast")
        parser.add_argument("--accounts", type=int, default=300)
        parser.add_argument("--origins", type=int, default=60, help="distinct client IP addresses")
        parser.add_argument("--concurrency", type=int, default=1,
                            help="worker threads calling the engine at once, as concurrent API requests would")
        parser.add_argument("--money-out", action="store_true",
                            help="turn on the outflow breaker and beneficiary control")
        parser.add_argument("--target-ms", type=float, default=150.0,
                            help="the p99 an inline decision should stay under (default 150)")
        parser.add_argument("--seed", type=int, default=7)
        parser.add_argument("--json", dest="json_path", help="also write the full report here")

    def handle(self, *args, **options):
        if options["events"] < 1 or options["concurrency"] < 1:
            raise CommandError("--events and --concurrency must be at least 1")

        # Alerts on high-risk decisions go to the channel layer. Without its
        # Redis backend installed, use the in-memory one and say so, rather
        # than fail on the first high-risk event.
        self.channel_layer = settings.CHANNEL_LAYERS["default"]["BACKEND"].rsplit(".", 1)[-1]
        if "redis" in self.channel_layer.lower() and importlib.util.find_spec("channels_redis") is None:
            settings.CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
            self.channel_layer = "InMemoryChannelLayer (channels_redis not installed)"

        old_name = connection.creation.create_test_db(verbosity=0, autoclobber=True)
        try:
            report = self.benchmark(options)
        finally:
            connections.close_all()
            connection.creation.destroy_test_db(old_name, verbosity=0)

        self.print_report(report, options)
        if options["json_path"]:
            with open(options["json_path"], "w") as handle:
                json.dump(report, handle, indent=2)
            self.stdout.write(f"\nFull report written to {options['json_path']}")

    # -- the run -----------------------------------------------------------------

    def benchmark(self, options):
        from asgiref.sync import async_to_sync
        from core.audit.auditor import Auditor
        from core.models import Application, Organization, User

        owner = User.objects.create_user(email=f"bench-{uuid.uuid4().hex[:8]}@example.invalid",
                                         password=uuid.uuid4().hex)
        organization = Organization.objects.create(name="Latency benchmark", owner=owner)
        application = Application.objects.create(
            name="Latency benchmark", organization=organization, enforcement="enforcing",
        )
        policy = application.policy
        if options["money_out"]:
            for field, value in MONEY_OUT_POLICY.items():
                setattr(policy, field, value)
            policy.save(update_fields=list(MONEY_OUT_POLICY))
            policy.refresh_from_db()

        traffic = Traffic(seed=options["seed"], accounts=options["accounts"],
                          origins=options["origins"], money_out=options["money_out"])
        events = [traffic.next() for _ in range(options["warmup"] + options["events"])]
        warmup, measured = events[:options["warmup"]], events[options["warmup"]:]

        audit = async_to_sync(Auditor.audit)

        def run(item):
            kind, event = item
            started = time.perf_counter()
            result = audit(event, policy)
            elapsed = (time.perf_counter() - started) * 1000
            return kind, elapsed, getattr(result, "audit_id", None)

        def in_workers(items):
            # Each worker is one thread, as each API request is, and closes
            # its own database connection when done: Django's connections are
            # per thread, and one left open stops the test database from
            # being dropped.
            work, results, failures = queue.Queue(), [None] * len(items), []
            for index, item in enumerate(items):
                work.put((index, item))

            def worker():
                try:
                    while True:
                        try:
                            index, item = work.get_nowait()
                        except queue.Empty:
                            return
                        results[index] = run(item)
                except BaseException as error:
                    failures.append(error)
                finally:
                    connections.close_all()

            threads = [threading.Thread(target=worker) for _ in range(options["concurrency"])]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            if failures:
                raise failures[0]
            return results

        history = in_workers(warmup)
        self.spread(history, options["history_days"])
        wall_started = time.perf_counter()
        samples = in_workers(measured)
        wall_seconds = time.perf_counter() - wall_started

        return self.summarise(samples, wall_seconds, options)

    def summarise(self, samples, wall_seconds, options):
        from core.models import AuditLog

        end_to_end = [elapsed for _, elapsed, _ in samples]
        by_kind = defaultdict(list)
        for kind, elapsed, _ in samples:
            by_kind[kind].append(elapsed)

        decision, stages, rules = [], defaultdict(list), defaultdict(list)
        rule_status = defaultdict(lambda: defaultdict(int))
        ids = [audit_id for _, _, audit_id in samples if audit_id]
        for context in AuditLog.objects.filter(id__in=ids).values_list("context", flat=True).iterator():
            timings = (context or {}).get("timings")
            if not timings:
                continue
            decision.append(timings["decision_ms"])
            for span in timings["spans"]:
                if span["name"] == "flit.rule":
                    name = span["attributes"]["rule"]
                    rules[name].append(span["duration_ms"])
                    rule_status[name][span["status"]] += 1
                else:
                    label = span["name"]
                    phase = (span.get("attributes") or {}).get("phase")
                    stages[f"{label} ({phase})" if phase else label].append(span["duration_ms"])

        overall = percentiles(end_to_end)
        return dict(
            environment=self.environment(options),
            throughput_per_second=round(len(samples) / wall_seconds, 1) if wall_seconds else None,
            end_to_end_ms=overall,
            meets_target=overall["p99"] < options["target_ms"],
            by_event_ms={kind: percentiles(values) for kind, values in sorted(by_kind.items())},
            decision_ms=percentiles(decision),
            stages_ms={name: percentiles(values) for name, values in stages.items()},
            rules_ms={
                name: dict(percentiles(values), statuses=dict(rule_status[name]))
                for name, values in rules.items()
            },
            spans_recorded=bool(decision),
        )

    @staticmethod
    def spread(history, days):
        """
        Move the warm-up decisions back in time, evenly over `days`, keeping
        their order. Run back to back, a few thousand decisions land in a few
        minutes, so every window a rule reads (an origin's hour, an account's
        day) is full, and the benchmark measures an attack, not a Tuesday.
        """
        from datetime import timedelta
        from django.utils import timezone
        from core.models import AuditLog

        ids = [audit_id for _, _, audit_id in history if audit_id]
        if days <= 0 or not ids:
            return

        rows = list(AuditLog.objects.filter(id__in=ids).order_by("timestamp", "id").only("id", "timestamp"))
        span, now = timedelta(days=days), timezone.now()
        for index, row in enumerate(rows):
            # The newest lands a minute ago, so nothing overlaps what is measured.
            row.timestamp = now - timedelta(minutes=1) - span * (1 - index / len(rows))
        AuditLog.objects.bulk_update(rows, ["timestamp"], batch_size=1000)

    def environment(self, options):
        from kernel.config import Config

        return dict(
            events=options["events"], warmup=options["warmup"], concurrency=options["concurrency"],
            history_days=options["history_days"],
            accounts=options["accounts"], origins=options["origins"], money_out=options["money_out"],
            seed=options["seed"], target_p99_ms=options["target_ms"],
            database=connection.vendor,
            cache=settings.CACHES["default"]["BACKEND"].rsplit(".", 1)[-1],
            channel_layer=self.channel_layer,
            domain_lookups=bool(getattr(Config, "domain_lookups_enabled", False)),
            chain_lookups=bool(getattr(Config, "chain_lookups_enabled", False)),
            geoip=bool(os.environ.get("GEOIP_DB_PATH")),
            python=platform.python_version(), machine=platform.machine(), cpus=os.cpu_count(),
        )

    # -- output ------------------------------------------------------------------

    def print_report(self, report, options):
        env = report["environment"]
        write = self.stdout.write

        spread = (f"spread over {env['history_days']:g} days" if env["history_days"] > 0
                  else "all in the last few minutes (stress)")
        write(f"\nFLIT decision latency: {env['events']} events after {env['warmup']} warm-up "
              f"({spread}), concurrency {env['concurrency']}, money-out controls "
              f"{'on' if env['money_out'] else 'off'}")
        write(f"database {env['database']}, cache {env['cache']}, domain lookups "
              f"{'on' if env['domain_lookups'] else 'off'}, chain lookups "
              f"{'on' if env['chain_lookups'] else 'off'}, GeoIP {'on' if env['geoip'] else 'off'}, "
              f"Python {env['python']} on {env['machine']} ({env['cpus']} CPUs)")
        if env["database"] == "sqlite" or env["cache"] == "LocMemCache":
            write(self.style.WARNING(
                "SQLite or an in-process cache: these numbers flatter production. "
                "Run against Postgres and Redis before quoting them."
            ))

        def row(label, stats, width=44):
            if not stats:
                return f"  {label:<{width}} {'-':>8}"
            return (f"  {label:<{width}} {stats['p50']:>8.1f} {stats['p95']:>8.1f} "
                    f"{stats['p99']:>8.1f} {stats['max']:>8.1f} {stats['n']:>6}")

        header = f"  {'':<44} {'p50':>8} {'p95':>8} {'p99':>8} {'max':>8} {'n':>6}"

        write("\nEnd to end, milliseconds (engine plus the write that records it)")
        write(header)
        write(row("all events", report["end_to_end_ms"]))
        for kind, stats in report["by_event_ms"].items():
            write(row(f"  {kind}", stats))
        write(f"\nThroughput: {report['throughput_per_second']} decisions a second")

        verdict = "PASS" if report["meets_target"] else "MISS"
        style = self.style.SUCCESS if report["meets_target"] else self.style.ERROR
        write(style(f"Inline target, p99 under {env['target_p99_ms']:.0f} ms: {verdict} "
                    f"(p99 {report['end_to_end_ms']['p99']:.1f} ms)"))

        if not report["spans_recorded"]:
            write("\nNo stage timings were recorded on the decisions, so there is no breakdown. "
                  "This build's auditor does not record spans.")
            return

        write("\nDecision only, without the record write")
        write(header)
        write(row("decision", report["decision_ms"]))

        write("\nStages, by p99")
        write(header)
        for name, stats in sorted(report["stages_ms"].items(), key=lambda item: -item[1]["p99"]):
            write(row(name, stats))

        write("\nRules, slowest 15 by p99 (rules run concurrently, so these overlap)")
        write(header)
        ranked = sorted(report["rules_ms"].items(), key=lambda item: -item[1]["p99"])
        for name, stats in ranked[:15]:
            unhealthy = {status: count for status, count in stats["statuses"].items() if status != "ok"}
            suffix = f"  {unhealthy}" if unhealthy else ""
            write(row(name, stats) + suffix)
