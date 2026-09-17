import ipaddress
from devkit import undefined
from abc import ABCMeta, abstractmethod
from devkit.checks import is_present, is_dense_str
from devkit.messages import msg_void_or_dense_string
from core.messages.networks import msg_void_or_ip_address


class EventError(Exception):
    pass


class BaseEvent(metaclass=ABCMeta):
    attributes = list()

    @abstractmethod
    def verify(self, policy=None):
        pass

    def __init__(self, **kwargs):
        for attribtute in self.attributes:
            setattr(self, attribtute, kwargs.get(attribtute, undefined))

        self.extra = dict(item for item in kwargs.items() if item[0] not in self.attributes)

    def verify_network_attrs(self):
        """Validate the optional end-user `ip_address` and `user_agent` attributes."""
        errors = list()

        if is_present(self.ip_address):
            try:
                ipaddress.ip_address(self.ip_address)
            except (TypeError, ValueError):
                errors.append(msg_void_or_ip_address.new(path="ip_address"))

        if is_present(self.user_agent) and not is_dense_str(self.user_agent):
            errors.append(msg_void_or_dense_string.new(path="user_agent"))

        return errors
