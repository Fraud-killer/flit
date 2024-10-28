from django.db.models import Q


def is_user_password(value):
    return (
        isinstance(value, str)
        and len(value) >= 8
        and value.strip()
    )


def is_unique_user_email(email, ignore_user_id=None):
    from core.models import User

    params = Q(email__iexact=email)

    if ignore_user_id is not None:
        params &= ~Q(id=ignore_user_id)

    return not User.objects.filter(params).exists()
