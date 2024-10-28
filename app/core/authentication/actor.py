from core.models import User, Application


class Actor:
    def __init__(self, entity=None):
        self.entity = entity

    @property    
    def is_user(self):
        return isinstance(self.entity, User)

    @property    
    def is_application(self):
        return isinstance(self.entity, Application)
