from devkit.messages import (
    msg_dense_string,
    msg_void_or_dense_string,
)

from devkit.checks import is_present, is_dense_str

from .base_event import BaseEvent


class ClientEvent(BaseEvent):
    account_id_is_event_id = True

    # `action` names what happened, e.g. login, password_change, email_change,
    # phone_change or new_device_login (read by AccountTakeoverRule).
    attributes = ["id", "visit_id", "ip_address", "user_agent", "action"]

    def verify(self, policy=None):
        errors = list()

        if not is_dense_str(self.id):
            errors.append(msg_dense_string.new(path="id"))

        if (
            is_present(self.visit_id)
            and not is_dense_str(self.visit_id)
        ):
            message = msg_void_or_dense_string
            errors.append(message.new(path="visit_id"))

        if is_present(self.action) and not is_dense_str(self.action):
            errors.append(msg_void_or_dense_string.new(path="action"))

        errors.extend(self.verify_network_attrs())

        return errors
