from bootkit.mezage import Mezage


mzg_unique_user_email = (
    Mezage(
        code="unique_user_email",
        text="Already taken by another user",
    )
)


mzg_user_reference_exist = (
    Mezage(
        code="user_reference_exist",
        text="Must refer to an existing user record",
    )
)


mzg_user_password = (
    Mezage(
        code="user_password",
        text="Must be non-blank and at least 8 characters long",
    )
)
