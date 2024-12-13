from core.models import Policy
from authentication.actor import Actor
from devkit.guard_meta import GuardMeta


class PolicyGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Policy):
    pass
