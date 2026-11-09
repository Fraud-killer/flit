from devkit.message import Message


msg_outflow_config = Message(
    code="outflow_config",
    text="This money-out configuration is not valid",
)

msg_outflow_trip_exist = Message(
    code="outflow_trip_exist",
    text="Must refer to an outflow trip on this application",
)

msg_outflow_trip_released = Message(
    code="outflow_trip_released",
    text="This outflow trip has already been released",
)

msg_beneficiary_entries = Message(
    code="beneficiary_entries",
    path="beneficiaries",
    text=(
        "Send between 1 and 1000 entries, each with initiator_id, client_id and "
        "counterparty_id, and counterparty_bank where the bank has one"
    ),
)
