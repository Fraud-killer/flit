from core.auth.actor import Actor
from core.models import Organization
from devkit.guard_meta import GuardMeta


class OrganizationGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Organization):
    pass
