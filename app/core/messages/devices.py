from devkit.message import Message


msg_no_query_id_device = (
    Message(
        code="no_query_id_device",
        text="No device found for the query id provided",
    )
)


msg_query_dvc_unregistered = (
    Message(
        code="query_device_unregistered",
        text="Device for the query id provided is not registered",
    )
)
