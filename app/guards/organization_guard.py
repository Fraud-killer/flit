from core.models import Organization
from authentication.actor import Actor
from devkit.guard_meta import GuardMeta


class OrganizationGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Organization):
    pass
