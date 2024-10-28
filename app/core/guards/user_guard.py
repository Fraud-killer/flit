from core.models import User
from bootkit.guard_meta import GuardMeta
from core.authentication.actor import Actor


class UserGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=User):
    pass
