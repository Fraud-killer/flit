from .message import Message


msg_uuid = (
    Message(
        code="uuid",
        text="Must be of uuid type",
    )
)


msg_email = (
    Message(
        code="email",
        text="Must be a valid email address",
    )
)


msg_hosts = (
    Message(
        code="hosts",
        text="Must be an array of host names",
    )
)


msg_present = (
    Message(
        code="present",
        text="Must be provided and cannot be null",
    )
)


msg_bool = (
    Message(
        code="bool",
        text="Must be of boolean type",
    )
)


msg_to_bool = (
    Message(
        code="to_bool",
        text="Must resolve to a boolean value",
    )
)


msg_dict = (
    Message(
        code="dict",
        text="Must be of dict type",
    )
)


msg_required = (
    Message(
        code="required",
        text="Is a required property",
    )
)


msg_extra_props = (
    Message(
        code="extra_props",
        text="Has extra properties",
    )
)


msg_invalid_prop_names = (
    Message(
        code="invalid_prop_names",
        text="Has invalid property names",
    )
)


msg_date = (
    Message(
        code="date",
        text="Must be of date type",
    )
)


msg_datetime = (
    Message(
        code="datetime",
        text="Must be of datetime type",
    )
)


msg_to_date = (
    Message(
        code="to_date",
        text="Must resolve to a date object",
    )
)


msg_to_datetime = (
    Message(
        code="to_datetime",
        text="Must resolve to a datetime object",
    )
)


msg_null_or_to_date = (
    Message(
        code="null_or_to_date",
        text="Must be null or resolve to date",
    )
)


msg_null_or_to_datetime = (
	Message(
        code="null_or_to_datetime",
        text="Must be null or resolve to datetime",
    )
)


msg_in_choices = (
    Message(
        code="in_choices",
        text="Must be one of the available choices",
    )
)


msg_void_or_decimal = (
	Message(
        code="void_or_decimal",
        text="Must be optional, null or a decimal number",
    )
)


msg_not_blank = (
    Message(
        code="not_blank",
        text="Cannot be a blank string",
    )
)


msg_trimmed_string = (
    Message(
        code="trimmed_string",
        text="Must be a whitespace-trimmed string",
    )
)


msg_dense_string = (
    Message(
        code="dense_string",
        text="Must be a non-blank and whitespace-free string",
    )
)


msg_void_or_dense_string = (
	Message(
        code="void_or_dense_string",
        text="Must be optional, null or a non-blank, whitespace-free string",
    )
)
