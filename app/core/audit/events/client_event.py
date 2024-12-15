from devkit.messages import (
    msg_dense_string,
    msg_void_or_dense_string,
)

from devkit.checks import is_present, is_dense_str

from .base_event import BaseEvent


class ClientEvent(BaseEvent):
    attributes = ["id", "visit_id"]

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

        return errors
