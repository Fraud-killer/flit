from str2bool import str2bool


def to_bool(value):
    value = str2bool(str(value))
    if value is not None: return value
    raise ValueError("Cannot resolve to boolean")
