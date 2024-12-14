from auth.actor import Actor
from core.models import Application
from devkit.guard_meta import GuardMeta


class ApplicationGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Application):
    def can_manage(self):
        self.ensure_access(
            self.resource and (
                (
                    self.actor.is_application
                    and str(self.actor.entity.id) == str(self.resource.id)
                )
                or
                (
                    self.actor.is_user
                    and str(self.actor.entity.id) == str(self.resource.organization.owner.id)
                )
            )
        )
