from core.auth.actor import Actor
from core.models import Device
from devkit.guard_meta import GuardMeta


class DeviceGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Device):
    def can_create(self, application):
        self.ensure_access(
            self.actor and (
                (
                    self.actor.is_application
                    and str(self.actor.entity.id) == str(application.id)
                )
                or
                (
                    self.actor.is_user
                    and str(self.actor.entity.id) == str(application.organization.owner.id)
                )
            )
        )
