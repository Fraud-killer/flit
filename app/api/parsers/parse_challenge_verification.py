from devkit import undefined
from devkit.struct import Struct
from core.models import Challenge
from devkit.checks import is_uuid_str, is_dense_str
from devkit.messages import msg_uuid, msg_required, msg_dense_string
from core.messages.challenges import msg_challenge_ref_exist

from .parse_application_id import parse_application_id


def parse_challenge_verification(id, challenge_id, request):
    response = request.data.get("response", undefined)
    remote_ip = request.data.get("remote_ip", None)

    errors = list()
    challenge = None
    application = parse_application_id(id, errors)

    if response is undefined:
        errors.append(msg_required.new(path="response"))
    elif not is_dense_str(response):
        errors.append(msg_dense_string.new(path="response"))

    if not is_uuid_str(challenge_id):
        errors.append(msg_uuid.new(path="challenge_id"))
    elif application:
        challenge = Challenge.objects.filter(
            application_id=application.id, id=challenge_id,
        ).select_related("application").first()

        if not challenge:
            errors.append(msg_challenge_ref_exist.new(path="challenge_id"))

    data = None if errors else (
        Struct(
            challenge=challenge,
            response=response,
            remote_ip=remote_ip,
            application=application,
        )
    )

    return (data, errors)
