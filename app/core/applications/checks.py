from bootkit import execute
from django.db.models import Q
from kernel.mcrypt import decrypt
from bootkit.checks import is_dense_string, is_trimmed_string


def is_app_secret_key(value):
    return is_dense_string(value) and len(value) == 30


def is_app_encrypted_secret_key(value):
    value, error = execute(decrypt, value)
    return not error and is_app_secret_key(value)


def is_app_device_sdk_key(data):
    return (
        isinstance(data, dict)
        and set(data.keys()) == {
            "id",
            "name",
            "token",
        }
        and is_dense_string(data["id"])
        and is_dense_string(data["token"])
        and is_trimmed_string(data["name"])
    )


def is_app_encrypted_device_sdk_key(value):
    data, error = execute(decrypt, value)
    return not error and is_app_device_sdk_key(data)


def app_has_policy(app_id, ignore_policy_id=None):
    from core.models import Policy

    params = Q(application_id=app_id)

    if ignore_policy_id is not None:
        params &= ~Q(id=ignore_policy_id)

    return Policy.objects.filter(params).exists()


def is_unique_app_name_in_org(name, org_id, ignore_app_id=None):
    from core.models import Application

    params = Q(name__iexact=name, organization_id=org_id)

    if ignore_app_id is not None: params &= ~Q(id=ignore_app_id)

    return not Application.objects.filter(params).exists()
