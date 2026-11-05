from core.auth.actor import Actor
from core.models import Organization
from devkit.guard_meta import GuardMeta


class OrganizationGuard(metaclass=GuardMeta, actor_type=Actor, resource_type=Organization):
    def can_manage(self):
        """Only a signed-in owner. An application key is not its organization."""
        self.ensure_access(
            self.resource is not None
            and self.actor.is_user
            and (
                getattr(self.actor.entity, "is_staff", False)
                or str(self.actor.entity.id) == str(self.resource.owner_id)
            )
        )
