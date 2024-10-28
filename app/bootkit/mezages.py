from .mezage import Mezage


mzg_uuid = Mezage(code="uuid", text="Must be of uuid type")

mzg_email = Mezage(code="email", text="Must be a valid email address")

mzg_hosts = Mezage(code="hosts", text="Must be an array of host names")

mzg_bool = Mezage(code="bool", text="Must be of boolean type")

mzg_to_bool = Mezage(code="to_bool", text="Must resolve to a boolean value")

mzg_mapping = Mezage(code="mapping", text="Must be of mapping type")

mzg_req_prop = Mezage(code="req_prop",  text="Is a required property")

mzg_unexpected_props = Mezage(code="unexpected_props", text="Has unexpected properties")

mzg_invalid_prop_names = Mezage(code="invalid_prop_names", text="Has invalid property names")

mzg_date = Mezage(code="date", text="Must be of date type")

mzg_datetime = Mezage(code="datetime", text="Must be of datetime type")

mzg_to_date = Mezage(code="to_date", text="Must resolve to a date object")

mzg_to_datetime = Mezage(code="to_datetime", text="Must resolve to a datetime object")

mzg_null_or_to_date = Mezage(code="null_or_to_date", text="Must be null or resolve to date")

mzg_null_or_to_datetime = (
	Mezage(
        code="null_or_to_datetime",
        text="Must be null or resolve to datetime",
    )
)

mzg_in_choices = Mezage(code="in_choices", text="Must be one of the available choices")

mzg_not_blank = Mezage(code="not_blank", text="Cannot be a blank string")

mzg_trimmed_string = Mezage(code="trimmed_string", text="Must be a space trimmed string")

mzg_dense_string = Mezage(code="dense_string", text="Must be a non-blank and no-whitespace string")

mzg_opt_null_or_dense_string = (
	Mezage(
        code="opt_null_or_dense_string",
        text="Optional, otherwise must be null or a non-blank, whitespace-free string",
    )
)
