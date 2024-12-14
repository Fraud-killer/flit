import re
import json
from uuid import UUID
from datetime import date, datetime

from . import execute
from .casts import to_bool


var_regex = r"(?:[a-z_][a-z0-9_]*)"
key_regex = fr"(?:(?:\d+)|{var_regex})"
path_regex = fr"(?:(?:{key_regex}\.)*{key_regex})"


def is_array(value):
    return type(value) in (set, list, tuple)


def can_be_json(value):
    return not execute(json.dumps, value)[1]


def can_be_bool(value):
    return not execute(to_bool, value)[1]


def is_uuid_str(value):
    return isinstance(value, str) and not execute(UUID, value)[1]


def is_dense_str(value):
    return isinstance(value, str) and value.strip() and not bool(re.search(r"\s", value))


def is_trimmed_str(value):
    return isinstance(value, str) and not re.search(r"(?:^\s|\s$)", value)


def is_var_str(value):
    return isinstance(value, str) and bool(re.fullmatch(var_regex, value, re.I))


def is_key_str(value):
    return isinstance(value, str) and bool(re.fullmatch(key_regex, value, re.I))


def is_path_str(value):
    return isinstance(value, str) and bool(re.fullmatch(path_regex, value, re.I))


def can_be_date(value):
    return isinstance(value, date) or not execute(date.fromisoformat, value)[1]


def can_be_datetime(value):
    return isinstance(value, datetime) or not execute(datetime.fromisoformat, value)[1]
