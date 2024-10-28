from core.models import Application
from bootkit.guard_meta import GuardMeta
from core.authentication.actor import Actor


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
