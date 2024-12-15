import json
from hashlib import sha256
from base64 import b64encode


undefined = type("undefined", tuple(), {
    "__bool__": lambda _: False,
})


def create_hash_value(value, hasher=sha256):
    value_json = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    )

    value_bytes = value_json.encode("utf-8")
    value_base64_bytes = b64encode(value_bytes)

    hashobj = hasher()
    hashobj.update(value_base64_bytes)

    return hashobj.hexdigest()


def execute(callback, *args, **kwargs):
    try: return (callback(*args, **kwargs), None)
    except Exception as error: return (None, error)
