from core.models import User
from authentication.actor import Actor
from devkit.guard_meta import GuardMeta


class UserGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=User):
    pass
