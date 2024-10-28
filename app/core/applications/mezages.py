from bootkit.mezage import Mezage


mzg_app_has_policy = (
    Mezage(
        code="app_has_policy",
        text="Has been associated with a policy",
    )
)


mzg_app_secret_key = (
    Mezage(
        code="app_secret_key",
        text="Must be a valid application secret key",
    )
)


mzg_unique_app_name_in_org = (
    Mezage(
        code="unique_app_name_in_org",
        text="Already in use within the organization",
    )
)


mzg_app_ref_exist = (
    Mezage(
        code="app_ref_exist",
        text="Must refer to an existing application record",
    )
)


mzg_app_has_device_sdk_key = (
    Mezage(
        code="app_has_device_sdk_key",
        text="Already has a device sdk key set",
    )
)


mzg_app_device_sdk_key = (
    Mezage(
        code="app_device_sdk_key",
        text="Must be a valid application device sdk key",
    )
)


mzg_null_or_app_device_sdk_key = (
    Mezage(
        code="null_or_app_device_sdk_key",
        text="Must be null or a valid application device sdk key",
    )
)
