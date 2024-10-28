from bootkit.mezage import Mezage


mzg_action_forbidden = (
    Mezage(
        code="action_forbidden",
        text="Not allowed to perform this action",
    )
)


mzg_invalid_credentials = (
    Mezage(
        code="invalid_credentials",
        text="The provided credentials are invalid",
    )
)


mzg_auth_required = (
    Mezage(
        code="auth_required",
        text="Must authenticate to perform this action",
    )
)
