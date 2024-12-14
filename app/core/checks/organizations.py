from django.db.models import Q


def is_unique_org_name_for_owner(name, owner_id, ignore_org_id=None):
    from core.models import Organization

    params = Q(name__iexact=name, owner_id=owner_id)

    if ignore_org_id is not None: params &= ~Q(id=ignore_org_id)

    return not Organization.objects.filter(params).exists()
