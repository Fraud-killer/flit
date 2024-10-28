from core.models import Organization
from bootkit.guard_meta import GuardMeta
from core.authentication.actor import Actor


class OrganizationGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Organization):
    pass
