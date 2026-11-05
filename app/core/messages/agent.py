from devkit.message import Message


msg_agent_disabled = Message(
    code="agent_disabled",
    text="Agent FLIT is off. Set AGENT_ENABLED and enable it on the agent policy.",
)

msg_agent_loosening = Message(
    code="agent_policy_loosening_forbidden",
    path="agent_policy",
    text=(
        "This change would let the agent do more on its own. An application key may only "
        "tighten the agent's policy; a signed-in owner of the organization must make this change."
    ),
)

msg_person_required = Message(
    code="person_required",
    text="A signed-in person must do this; an application key cannot.",
)

msg_playbook_invalid = Message(
    code="playbook_invalid",
    path="playbook",
    text="The playbook could not be parsed",
)

msg_investigation_state = Message(
    code="investigation_state",
    text="The investigation is not in a state where that is possible",
)

msg_rules_invalid = Message(
    code="agent_rules_invalid",
    text="Rules must be tool names, optionally with a subject pattern in parentheses",
)
