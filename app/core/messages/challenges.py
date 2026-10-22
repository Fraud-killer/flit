from devkit.message import Message


msg_challenge_ref_exist = (
    Message(
        code="challenge_ref_exist",
        text="Must refer to a challenge belonging to this application",
    )
)

msg_challenge_unavailable = (
    Message(
        code="challenge_unavailable",
        text="The challenge could not be verified; try again",
    )
)
