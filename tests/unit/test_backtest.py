"""
Tests for the backtest harness: column mapping, loading exports, replaying
history through the real rules, the calibration report, and portfolio overlap.
"""

import csv
import json
from datetime import datetime, timedelta, timezone as datetime_timezone

import pytest


NOW = datetime.now(datetime_timezone.utc)


MAPPING = {
    "fields": {
        "id": "txn_ref",
        "type": "direction",
        "amount": "amount_minor",
        "client_id": "customer",
        "counterparty_id": "peer",
        "device_id": "device",
        "ip_address": "ip",
    },
    "constants": {"currency_code": "NGN"},
    "values": {"type": {"IN": "credit", "OUT": "debit"}},
    "label_field": "outcome",
    "labels": {"chargeback": "chargeback", "settled": "legit"},
    "amount_scale": 0.01,
    "timestamp_field": "created_at",
}


def write_csv(path, rows):
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    return str(path)


def write_mapping(path, overrides=None):
    configuration = {**MAPPING, **(overrides or {})}

    with open(path, "w") as handle:
        json.dump(configuration, handle)

    return str(path)


def transaction(reference, direction="OUT", **overrides):
    row = dict(
        txn_ref=reference,
        direction=direction,
        amount_minor=25000,
        customer="cust_1",
        peer="merchant_1",
        device="dev_1",
        ip="81.2.69.160",
        created_at=(NOW - timedelta(days=3)).isoformat(),
        outcome="settled",
    )
    row.update(overrides)
    return row


class TestMapping:
    def mapping(self, **overrides):
        from core.backtest.mapping import EventMapping

        return EventMapping({**MAPPING, **overrides})

    def test_reads_a_row_into_event_attributes(self):
        item = self.mapping().read(transaction("tx_1", direction="IN"))

        assert item.attributes["id"] == "tx_1"
        assert item.attributes["type"] == "credit"
        assert item.attributes["currency_code"] == "NGN"
        assert item.attributes["counterparty_id"] == "merchant_1"
        # Minor units are scaled into the major units the rules compare.
        assert item.attributes["amount"] == 250.0
        assert item.device_id == "dev_1"
        assert item.label == "legit"

    def test_unmapped_outcomes_are_left_unlabelled(self):
        item = self.mapping().read(transaction("tx_1", outcome="pending"))

        assert item.label is None

    def test_blank_values_are_skipped(self):
        item = self.mapping().read(transaction("tx_1", peer="", ip=""))

        assert "counterparty_id" not in item.attributes
        assert "ip_address" not in item.attributes

    def test_reads_several_timestamp_formats(self):
        from core.backtest.mapping import parse_timestamp

        assert parse_timestamp("2026-01-02T03:04:05Z").year == 2026
        assert parse_timestamp("2026-01-02 03:04:05").tzinfo is not None
        assert parse_timestamp("1767322445").year == 2026

    def test_rejects_an_unreadable_timestamp(self):
        from core.backtest.mapping import MappingError

        with pytest.raises(MappingError):
            self.mapping().read(transaction("tx_1", created_at="last tuesday"))

    def test_rejects_an_incomplete_or_unknown_mapping(self):
        from core.backtest.mapping import EventMapping, MappingError

        with pytest.raises(MappingError):
            EventMapping({"fields": {"id": "ref"}})

        with pytest.raises(MappingError):
            EventMapping({"fields": {"id": "a", "type": "b", "client_id": "c", "nonsense": "d"}})


class TestLoader:
    def test_reads_csv_json_and_jsonl(self, tmp_path):
        from core.backtest.loader import iter_rows

        rows = [transaction("tx_1"), transaction("tx_2")]

        csv_path = write_csv(tmp_path / "export.csv", rows)
        assert len(list(iter_rows(csv_path))) == 2

        json_path = tmp_path / "export.json"
        json_path.write_text(json.dumps({"data": rows}))
        assert len(list(iter_rows(str(json_path)))) == 2

        jsonl_path = tmp_path / "export.jsonl"
        jsonl_path.write_text("\n".join(json.dumps(row) for row in rows))
        assert len(list(iter_rows(str(jsonl_path)))) == 2

    def test_rejects_unknown_files(self, tmp_path):
        from core.backtest.loader import iter_rows, LoaderError

        with pytest.raises(LoaderError):
            list(iter_rows(str(tmp_path / "missing.csv")))

        path = tmp_path / "export.xlsx"
        path.write_text("nope")

        with pytest.raises(LoaderError):
            list(iter_rows(str(path)))


class TestReplay:
    def replay(self, application, rows, **options):
        from core.backtest.mapping import EventMapping
        from core.backtest.replay import Replay

        replay = Replay(application=application, mapping=EventMapping(MAPPING), **options)
        results = replay.run(rows)

        return replay, results

    def test_replays_at_each_transaction_s_own_time(self, application, no_geoip):
        from core.models import AuditLog

        moment = NOW - timedelta(days=200)
        _, results = self.replay(application, [transaction("tx_old", created_at=moment.isoformat())])

        assert len(results) == 1
        log = AuditLog.objects.get(resource_id="tx_old")

        # Recorded in the past, not at replay time: every window-based rule
        # depends on this being true.
        assert abs((log.timestamp - moment).total_seconds()) < 5

    def test_replays_in_chronological_order(self, application, no_geoip):
        rows = [
            transaction("tx_late", created_at=(NOW - timedelta(days=1)).isoformat()),
            transaction("tx_early", created_at=(NOW - timedelta(days=10)).isoformat()),
        ]

        _, results = self.replay(application, rows)

        assert [row["event_id"] for row in results] == ["tx_early", "tx_late"]

    def test_labels_arrive_after_the_reporting_delay(self, application, no_geoip):
        from core.models import AuditLog

        moment = NOW - timedelta(days=30)
        rows = [transaction("tx_1", outcome="chargeback", created_at=moment.isoformat())]

        self.replay(application, rows, label_delay_days=14)

        log = AuditLog.objects.get(resource_id="tx_1")
        assert log.label == "chargeback"
        # Dated when it was reported, not when the payment happened.
        assert (log.labeled_at - moment).days == 14

    def test_a_label_is_not_visible_to_transactions_before_it_is_reported(self, application, no_geoip):
        """MuleNetworkRule must not see fraud that had not been reported yet."""
        from core.models import AuditLog

        first = NOW - timedelta(days=30)
        rows = [
            transaction("tx_fraud", customer="mule_1", outcome="chargeback",
                        created_at=first.isoformat()),
            transaction("tx_next", customer="mule_2",
                        created_at=(first + timedelta(days=1)).isoformat()),
            transaction("tx_later", customer="mule_3",
                        created_at=(first + timedelta(days=20)).isoformat()),
        ]

        _, results = self.replay(application, rows, label_delay_days=7)

        by_id = {row["event_id"]: row for row in results}

        # A day later the chargeback has not been reported yet.
        assert "mule_network_device" not in by_id["tx_next"]["factors"]
        # Twenty days later it has.
        assert "mule_network_device" in by_id["tx_later"]["factors"]
        assert AuditLog.objects.filter(label="chargeback").count() == 1

    def test_builds_the_device_graph_from_the_export(self, application, no_geoip):
        from core.models import DeviceIdentity, DeviceAccountLink

        rows = [
            transaction("tx_1", customer="cust_1", device="shared_device"),
            transaction("tx_2", customer="cust_2", device="shared_device"),
        ]

        self.replay(application, rows)

        device = DeviceIdentity.objects.get(external_id="shared_device")
        assert device.source == "flit"
        assert DeviceAccountLink.objects.filter(device=device).count() == 2

    def test_unusable_rows_are_skipped_and_reported(self, application, no_geoip):
        rows = [
            transaction("tx_ok"),
            transaction("tx_bad", direction="SIDEWAYS"),
            dict(transaction("tx_worse"), created_at=""),
        ]

        replay, results = self.replay(application, rows)

        assert [row["event_id"] for row in results] == ["tx_ok"]
        assert len(replay.skipped) == 2
        assert any("invalid event" in item["reason"] for item in replay.skipped)
        assert any("unreadable row" in item["reason"] for item in replay.skipped)

    def test_a_mule_pattern_is_caught_on_replay(self, application, no_geoip):
        opened = NOW - timedelta(days=5)
        rows = [
            transaction(f"tx_in_{index}", direction="IN", customer="mule", amount_minor=50000,
                        peer=f"victim_{index}", device="mule_device",
                        created_at=(opened + timedelta(minutes=index * 5)).isoformat())
            for index in range(6)
        ]
        rows.append(transaction("tx_out", customer="mule", amount_minor=290000, peer="herder",
                                device="mule_device", outcome="chargeback",
                                created_at=(opened + timedelta(minutes=40)).isoformat()))

        _, results = self.replay(application, rows)

        payout = next(row for row in results if row["event_id"] == "tx_out")
        assert "pass_through_funds" in payout["factors"]
        assert "many_unique_payers" in payout["factors"]
        assert payout["should_review"]


class TestReport:
    def results(self):
        return [
            dict(event_id="f1", timestamp=NOW, risk_score=0.8, risk_level="critical",
                 factors=["pass_through_funds", "req_event_attrs"], label="fraud"),
            dict(event_id="f2", timestamp=NOW, risk_score=0.6, risk_level="high",
                 factors=["many_unique_payers"], label="chargeback"),
            dict(event_id="g1", timestamp=NOW, risk_score=0.6, risk_level="high",
                 factors=["many_unique_payers"], label="legit"),
            dict(event_id="g2", timestamp=NOW, risk_score=0.0, risk_level="low",
                 factors=[], label="legit"),
        ]

    def build(self, results=None):
        from types import SimpleNamespace
        from core.backtest.report import build_report

        return build_report(
            results=self.results() if results is None else results,
            skipped=[],
            application=SimpleNamespace(name="Portfolio"),
            label_delay_days=7,
        )

    def test_measures_the_current_policy(self):
        report = self.build()
        current = report["current_policy"]

        # Only f1 (0.8) clears the 0.7 block threshold.
        assert current["blocked"] == 1
        assert current["caught_fraud"] == 1
        assert current["missed_fraud"] == 1
        assert current["false_positives"] == 0
        assert current["precision"] == 1.0
        assert current["recall"] == 0.5

    def test_the_curve_shows_the_cost_of_blocking_lower(self):
        report = self.build()
        point = next(p for p in report["threshold_curve"] if p["block_at"] == 0.6)

        assert point["caught_fraud"] == 2
        assert point["recall"] == 1.0
        # Catching the second fraud costs one good customer.
        assert point["false_positives"] == 1
        assert point["false_positive_rate"] == 0.5

    def test_ranks_rules_that_only_fire_on_fraud_first(self):
        report = self.build()
        rules = report["rules"]

        assert rules[0]["code"] == "pass_through_funds"
        assert rules[0]["only_on_fraud"] is True
        assert rules[1]["code"] == "many_unique_payers"
        assert rules[1]["lift"] == 1.0

        # Completeness markers are not rules and must not pad the table.
        assert "req_event_attrs" not in [rule["code"] for rule in rules]

    def test_says_so_when_there_are_no_labels(self):
        from core.backtest.report import format_report

        results = [dict(row, label=None) for row in self.results()]
        report = self.build(results)

        assert report["labels"]["fraud"] == 0
        assert report["current_policy"]["precision"] is None
        assert "cannot be measured" in format_report(report)

    def test_formats_without_crashing_on_an_empty_replay(self):
        from core.backtest.report import format_report

        report = self.build([])

        assert report["replayed"] == 0
        assert "no rules fired" in format_report(report)


class TestOverlap:
    def test_measures_shared_devices_and_known_fraud(self, application, second_application, no_geoip):
        from core.backtest.overlap import compare
        from core.backtest.mapping import EventMapping
        from core.backtest.replay import Replay
        from core.models import AuditLog

        def replay(target, rows):
            Replay(application=target, mapping=EventMapping(MAPPING)).run(rows)

        replay(application, [
            transaction("a1", customer="a_cust", device="device_only_a"),
            transaction("a2", customer="a_fraudster", device="ring_device", outcome="chargeback"),
        ])
        replay(second_application, [
            transaction("b1", customer="b_cust", device="device_only_b"),
            transaction("b2", customer="b_cust_2", device="ring_device"),
        ])

        assert AuditLog.objects.filter(label="chargeback").count() == 1

        result = compare(application, second_application)

        assert result["devices"]["shared"] == 1
        assert result["devices"]["first"] == 2
        # The fraud device from the first portfolio is known to the second.
        known = result["fraud_known_elsewhere"][application.name]
        assert known["fraud_devices"] == 1
        assert known["also_seen_elsewhere"] == 1
        assert known["share"] == 1.0

    def test_reports_nothing_shared_between_unrelated_portfolios(self, application, second_application, no_geoip):
        from core.backtest.overlap import compare
        from core.backtest.mapping import EventMapping
        from core.backtest.replay import Replay

        Replay(application=application, mapping=EventMapping(MAPPING)).run(
            [transaction("a1", customer="a_cust", device="device_a")]
        )
        Replay(application=second_application, mapping=EventMapping(MAPPING)).run(
            [transaction("b1", customer="b_cust", device="device_b")]
        )

        result = compare(application, second_application)

        assert result["devices"]["shared"] == 0
        assert result["fraud_known_elsewhere"][application.name]["share"] is None


class TestCommand:
    def test_runs_end_to_end(self, application, tmp_path, no_geoip):
        from io import StringIO
        from django.core.management import call_command

        rows = [
            transaction("tx_1", created_at=(NOW - timedelta(days=5)).isoformat()),
            transaction("tx_2", direction="IN", outcome="chargeback",
                        created_at=(NOW - timedelta(days=4)).isoformat()),
        ]

        output = StringIO()
        report_path = tmp_path / "report.json"

        call_command(
            "backtest",
            write_csv(tmp_path / "export.csv", rows),
            mapping=write_mapping(tmp_path / "mapping.json"),
            application=application.name,
            out=str(report_path),
            stdout=output,
        )

        assert "replayed 2 transactions" in output.getvalue()

        report = json.loads(report_path.read_text())
        assert report["replayed"] == 2
        assert report["labels"]["fraud"] == 1

    def test_refuses_an_unknown_application(self, tmp_path, db):
        from django.core.management import call_command
        from django.core.management.base import CommandError

        with pytest.raises(CommandError, match="No application named"):
            call_command(
                "backtest",
                write_csv(tmp_path / "export.csv", [transaction("tx_1")]),
                mapping=write_mapping(tmp_path / "mapping.json"),
                application="Nobody",
            )
