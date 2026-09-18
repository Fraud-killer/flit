from devkit.message import Message


msg_audit_ref_exist = (
    Message(
        code="audit_ref_exist",
        text="Must refer to an audit recorded for this application",
    )
)


msg_audit_or_event_id = (
    Message(
        code="audit_or_event_id",
        text="Either audit_id or event_id is required",
    )
)
