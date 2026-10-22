"""
Maps a merchant's export columns onto FLIT's event fields.

Every fintech names its columns differently, so a backtest is configured
with a small mapping file rather than by reshaping the export by hand:

    {
      "fields": {"id": "txn_ref", "amount": "amount_minor", "client_id": "customer_uuid"},
      "constants": {"currency_code": "NGN"},
      "values": {"type": {"IN": "credit", "OUT": "debit"}},
      "label_field": "outcome",
      "labels": {"chargeback": "chargeback", "confirmed_fraud": "fraud", "ok": "legit"},
      "amount_scale": 0.01,
      "timestamp_field": "created_at"
    }

`fields` maps FLIT's field name to the export's column. `values` and `labels`
are keyed the same way, by FLIT's field name rather than the column's.
"""

from datetime import datetime, timezone as datetime_timezone

from devkit.struct import Struct


EVENT_FIELDS = [
    "id",
    "type",
    "amount",
    "currency_code",
    "client_id",
    "counterparty_id",
    "account_age_days",
    "kyc_level",
    "ip_address",
    "user_agent",
    "visit_id",
    "visit_token",
    "status",
    "current_cumulative_balance",
    "daily_cumulative_debit_balance",
    # Payment-rule fields: not declared event attributes, so they travel in
    # `extra` and are read by the card testing and gateway pattern rules.
    "gateway_message",
    "card_fingerprint",
    "card_bin",
    # Crypto rails. Optional: only the crypto rules read them, and an export
    # without them replays exactly as before.
    "chain",
    "asset",
    "wallet_address",
    "counterparty_address",
    "transaction_hash",
    # Credential and signup surfaces. An export may mix event kinds — a
    # login, a reset, a registration and a payout from one origin replay in
    # true order only if they travel in one file — so these are accepted
    # alongside the money fields and the event kind decides which apply.
    "action",
    "auth_method",
    "second_factor",
    "email",
    "phone",
    "country",
    "referrer",
]

# Columns FLIT can use for device identity when there is no Fingerprint visit.
DEVICE_FIELDS = ["device_id"]

EVENT_TYPES = ("transaction", "authentication", "registration")


class MappingError(Exception):
    pass


class EventMapping:
    def __init__(self, configuration):
        self.fields = configuration.get("fields") or {}
        self.constants = configuration.get("constants") or {}
        self.values = configuration.get("values") or {}
        self.labels = configuration.get("labels") or {}
        self.label_field = configuration.get("label_field")
        self.amount_scale = configuration.get("amount_scale", 1)
        self.timestamp_field = configuration.get("timestamp_field", "timestamp")
        # Either one kind for the whole file (`event_type`), or a column
        # naming the kind per row (`event_type_field`). Transaction when
        # neither is given, so every existing mapping replays as before.
        self.event_type = configuration.get("event_type", "transaction")
        self.event_type_field = configuration.get("event_type_field")

        if self.event_type not in EVENT_TYPES:
            raise MappingError(f"event_type must be one of {EVENT_TYPES}")

        unknown = set(self.fields) - set(EVENT_FIELDS) - set(DEVICE_FIELDS)
        if unknown:
            raise MappingError(f"Unknown event fields in mapping: {sorted(unknown)}")

        required = ("id", "type", "client_id")
        if self.event_type_field or self.event_type != "transaction":
            # Each event kind verifies its own required attributes when it
            # is built; only the identifier is required of every row.
            required = ("id",)

        for name in required:
            if name not in self.fields and name not in self.constants:
                raise MappingError(f"Mapping must provide {name!r}")

    def event_type_for(self, row):
        if not self.event_type_field:
            return self.event_type

        kind = row.get(self.event_type_field) or self.event_type
        if kind not in EVENT_TYPES:
            raise MappingError(f"Unknown event type {kind!r} in column {self.event_type_field!r}")
        return kind

    @classmethod
    def load(cls, path):
        import json

        with open(path) as handle:
            return cls(json.load(handle))

    def read(self, row):
        """One export row -> (event attributes, device id, timestamp, label)."""
        attributes = dict(self.constants)

        for field, column in self.fields.items():
            value = row.get(column)
            if value in (None, ""):
                continue
            attributes[field] = self.translate(field, value)

        device_id = attributes.pop("device_id", None)

        return Struct(
            attributes=attributes,
            device_id=device_id,
            timestamp=self.timestamp(row),
            label=self.label(row),
            event_type=self.event_type_for(row),
        )

    def translate(self, field, value):
        mapped = self.values.get(field)

        if mapped:
            value = mapped.get(str(value), value)

        if field == "amount" or field.endswith("balance"):
            return round(float(value) * self.amount_scale, 2)

        if field == "account_age_days":
            return int(float(value))

        if field == "second_factor" and isinstance(value, str):
            # CSV carries booleans as text.
            return value.strip().lower() in ("true", "t", "1", "yes")

        return value

    def label(self, row):
        if not self.label_field:
            return None

        value = row.get(self.label_field)

        if value in (None, ""):
            return None

        return self.labels.get(str(value))

    def timestamp(self, row):
        value = row.get(self.timestamp_field)

        if value in (None, ""):
            raise MappingError(f"Row has no {self.timestamp_field!r}")

        return parse_timestamp(value)


def parse_timestamp(value):
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value).strip().replace("Z", "+00:00")

        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            try:
                moment = datetime.fromtimestamp(float(text), tz=datetime_timezone.utc)
            except ValueError:
                raise MappingError(f"Could not read timestamp {value!r}")

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime_timezone.utc)

    return moment
