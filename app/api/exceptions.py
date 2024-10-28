import json
from rest_framework import status
from rest_framework.response import Response
from bootkit.guard_meta import GuardAccessDenied
from rest_framework.views import exception_handler as default_exception_handler
from api.mezages import mzg_action_forbidden, mzg_auth_required, mzg_invalid_credentials
from rest_framework.exceptions import PermissionDenied, NotAuthenticated, AuthenticationFailed


NO_AUTH_HEADER = "HMAC,Bearer realm='api'"


def handle_permission_denied():
    return Response(
        dict(
            data=None,
            errors=[mzg_action_forbidden.new()],
        ),
        status=status.HTTP_403_FORBIDDEN,
    )


def handle_not_authenticated():
    return Response(
        dict(
            data=None,
            errors=[mzg_auth_required.new()],
        ),
        status=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": NO_AUTH_HEADER},
    )


def handle_authentication_failed(exception):
    context = json.loads(json.dumps(exception.detail))

    if not isinstance(context, dict):
        context = dict(message=context)

    return Response(
        dict(
            data=None,
            errors=[
                mzg_invalid_credentials
                    .new(context=context)
            ],
        ),
        status=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": exception.auth_header},
    )


def handle_any_exception(exception, context):
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
