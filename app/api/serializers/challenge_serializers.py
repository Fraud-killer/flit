def serialize_challenge(challenge, *, code=None):
    """
    A challenge as the merchant's server sees it.

    `code` is present only in the response to issuing an OTP, which is the one
    moment it exists: FLIT stores its digest and cannot produce it again.
    """
    data = dict(
        id=str(challenge.id),
        client_id=challenge.client_id,
        method=challenge.method,
        status=challenge.status,
        attempts=challenge.attempts,
        attempts_remaining=challenge.attempts_remaining,
        created_at=challenge.created_at,
        expires_at=challenge.expires_at,
        resolved_at=challenge.resolved_at,
    )

    if code is not None:
        data["code"] = code

    return data
