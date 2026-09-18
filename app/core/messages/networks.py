from devkit.message import Message


msg_void_or_user_agent = (
    Message(
        code="void_or_user_agent",
        text="Optional, otherwise must be a non-blank, whitespace-trimmed string",
    )
)


msg_void_or_ip_address = (
    Message(
        code="void_or_ip_address",
        text="Optional, otherwise must be a valid IPv4 or IPv6 address",
    )
)
