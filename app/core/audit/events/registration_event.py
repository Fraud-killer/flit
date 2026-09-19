from devkit.checks import is_present, is_dense_str
from devkit.messages import msg_dense_string, msg_void_or_dense_string

from .base_event import BaseEvent


class RegistrationEvent(BaseEvent):
    """
    An account being created — the moment before FLIT knows anything.

    There is no device history here, no transaction, no travel baseline. What
    the attacker did hand over is an address, an IP and a user agent, and a
    registration is the cheapest thing in the world to automate. So this is
    the surface abuse starts on, and the one FLIT was blindest to.
    """

    account_id_is_event_id = True
    event_type = "registration"

    attributes = [
        "id",
        "client_id",
        "visit_id",
        "visit_token",
        "ip_address",
        "user_agent",
        "email",
        "phone",
        "country",
        "referrer",
        "action",
    ]

    def verify(self, policy=None):
        errors = list()

        if not is_dense_str(self.id):
            errors.append(msg_dense_string.new(path="id"))

        for name in ("visit_id", "email", "phone", "country", "referrer", "action"):
            value = getattr(self, name)
            if is_present(value) and not is_dense_str(value):
                errors.append(msg_void_or_dense_string.new(path=name))

        errors.extend(self.verify_visit_attrs())
        errors.extend(self.verify_network_attrs())

        return errors
