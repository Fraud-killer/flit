"""Reads a merchant's export: CSV, JSON array, or newline-delimited JSON."""

import csv
import json
from pathlib import Path


class LoaderError(Exception):
    pass


def iter_rows(path):
    path = Path(path)

    if not path.exists():
        raise LoaderError(f"No such file: {path}")

    suffix = path.suffix.lower()

    if suffix == ".csv":
        yield from iter_csv(path)
    elif suffix in (".jsonl", ".ndjson"):
        yield from iter_jsonl(path)
    elif suffix == ".json":
        yield from iter_json(path)
    else:
        raise LoaderError(f"Unsupported file type: {suffix} (use .csv, .json or .jsonl)")


def iter_csv(path):
    with open(path, newline="") as handle:
        yield from csv.DictReader(handle)


def iter_jsonl(path):
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def iter_json(path):
    with open(path) as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        # Tolerate {"data": [...]} and {"transactions": [...]} wrappers.
        for key in ("data", "transactions", "results", "items"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break

    if not isinstance(payload, list):
        raise LoaderError("JSON file must contain a list of transactions")

    yield from payload
