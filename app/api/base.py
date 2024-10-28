from rest_framework import status
from rest_framework.response import Response


def build_api_response(*, data=None, errors=list(), status_code=None):
    data = None if errors else data

    if errors and status_code is None:
        status_code = status.HTTP_400_BAD_REQUEST

    return Response(dict(data=data, errors=errors), status=status_code)
