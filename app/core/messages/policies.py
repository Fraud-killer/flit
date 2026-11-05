from devkit.message import Message


msg_policy_loosening = (
    Message(
        code="policy_loosening_forbidden",
        path="policy",
        text=(
            "This change would make FLIT looser. An application key may only "
            "tighten policy; a signed-in owner of the organization must make this change."
        ),
    )
)

msg_weights_empty = (
    Message(
        code="weights_empty",
        path="weights",
        text="Weights cannot be empty or all zero; omit the field to leave them unchanged",
    )
)

msg_outbound_url = (
    Message(
        code="outbound_url",
        text=(
            "Must be an https URL FLIT may connect to: no credentials, no private, "
            "loopback or link-local address"
        ),
    )
)
