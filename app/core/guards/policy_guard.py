from core.models import Policy
from bootkit.guard_meta import GuardMeta
from core.authentication.actor import Actor


class PolicyGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Policy):
    pass
