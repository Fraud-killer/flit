class GuardError(Exception):
    pass


class GuardAccessDenied(Exception):
    pass


def ensure_access(condition):
    if condition == True: return None
    raise GuardAccessDenied("Access denied")


class GuardMeta(type):
    def __new__(mcls, name, bases, attrs, **options):
        error_messages = list()

        if list(set(options) - {"actor_type", "resource_type"}):
            error_messages.append("The permitted options are actor_type and resource_type")
 
        if not isinstance(options.get("resource_type"), type):
            error_messages.append("The resource type must be a native type object")

        if not isinstance(options.get("actor_type"), type):
            error_messages.append("The actor type must be a native type object")

        if "__init__" in attrs:
            error_messages.append("The initializer method is not supported")

        if error_messages: raise GuardError(f"{name}: {error_messages}")

        attrs.update(options)

        return super().__new__(mcls, name, bases, attrs)

    def __call__(cls, actor, resource=None):
        error_messages = list()

        if not isinstance(actor, cls.actor_type):
            type_name = cls.actor_type.__name__
            error_messages.append(f"Actor must be of {type_name} type")

        if not (resource is None or isinstance(resource, cls.resource_type)):
            type_name = cls.resource_type.__name__
            error_messages.append(f"Resource must be none or of {type_name} type")

        if error_messages:
            raise GuardError(f"{cls.__name__}: {error_messages}")

        instance = object.__new__(cls)
        instance.actor = actor
        instance.resource = resource
        instance.ensure_access = ensure_access

        return instance
