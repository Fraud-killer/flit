from auth.actor import Actor
from core.models import Policy
from devkit.guard_meta import GuardMeta


class PolicyGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Policy):
    pass
