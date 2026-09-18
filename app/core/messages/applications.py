from devkit.message import Message


msg_app_ref_exist = (
    Message(
        code="app_ref_exist",
        text="Must refer to an existing application record",
    )
)

msg_collect_key_exist = (
    Message(
        code="collect_key_exist",
        text="Must be a valid collection key for an application",
    )
)
