from rest_framework import status
from rest_framework.response import Response


def build_api_response(
    *,
    data=None,
    headers=None,
    errors=list(),
    status_code=None,
):
    data = None if errors else data

    if errors and status_code is None:
        status_code = status.HTTP_400_BAD_REQUEST

    payload = dict(data=data, errors=errors)

    return Response(payload, headers=headers, status=status_code)
