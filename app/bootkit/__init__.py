import json
import hashlib
from base64 import b64encode


undefined = type("undefined", tuple(), dict(
    __bool__=lambda _: False,
))


def execute(callback, *args, **kwargs):
    try: return (callback(*args, **kwargs), None)
    except Exception as error: return (None, error)


def create_hash_value(value, *, hasher=hashlib.sha256):
    value_json = json.dumps(value, sort_keys=True)
    value_bytes = value_json.encode("utf-8")
    value_base64 = b64encode(value_bytes)
    hashobj = hasher()
    hashobj.update(value_base64)
    return hashobj.hexdigest()
