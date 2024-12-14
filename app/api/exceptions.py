import json
from rest_framework import status
from devkit.message import Message
from api.base import build_api_response
from devkit.guard_meta import GuardAccessDenied
from rest_framework.views import exception_handler as default_exception_handler
from rest_framework.exceptions import PermissionDenied, NotAuthenticated, AuthenticationFailed


def handle_permission_denied():
    return build_api_response(
        errors=[
            Message(
                code="action_forbidden",
                text="Not allowed to perform this action",
            )
        ],
        status_code=status.HTTP_403_FORBIDDEN,
    )


def handle_authentication_failed(exception):
    payload = json.loads(json.dumps(exception.detail))

    context = (
        payload if isinstance(payload, dict)
        else dict(message=payload)
    )

    return build_api_response(
        errors=[
            Message(
                context=context,
                code="invalid_credentials",
                text="The provided credentials are invalid",
            )
        ],
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": exception.auth_header},
    )


def handle_not_authenticated():
    return build_api_response(
        errors=[
            Message(
                code="auth_required",
                text="Must authenticate to perform this action",
            )
        ],
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": "HMAC,Bearer realm='api'"},
    )


def handle_exception(exception, context):
    if isinstance(exception, NotAuthenticated):
        return handle_not_authenticated()

    if (
        isinstance(exception, PermissionDenied)
        or isinstance(exception, GuardAccessDenied)
    ):
        return handle_permission_denied()

    if isinstance(exception, AuthenticationFailed):
        return handle_authentication_failed(exception)

    return default_exception_handler(exception, context)
