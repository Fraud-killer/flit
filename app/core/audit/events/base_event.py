import ipaddress
from devkit import undefined
from abc import ABCMeta, abstractmethod
from devkit.checks import is_present, is_trimmed_str
from devkit.checks import is_dense_str
from devkit.messages import msg_void_or_dense_string
from core.messages.networks import msg_void_or_ip_address, msg_void_or_user_agent


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

    @property
    def account_id(self):
        """The merchant's identifier for the account behind the event."""
        value = getattr(self, "client_id", undefined)
        if not is_present(value):
            value = getattr(self, "id", undefined) if self.account_id_is_event_id else undefined
        return value if is_present(value) else None

    # ClientEvent.id identifies the client; TransactionEvent.id the transaction.
    account_id_is_event_id = False

    def verify_visit_attrs(self):
        """The visit token issued by /v1/collect, or Fingerprint's visit id."""
        if is_present(self.visit_token) and not is_dense_str(self.visit_token):
            return [msg_void_or_dense_string.new(path="visit_token")]

        return []

    def verify_network_attrs(self):
        """Validate the optional end-user `ip_address` and `user_agent` attributes."""
        errors = list()

        if is_present(self.ip_address):
            try:
                ipaddress.ip_address(self.ip_address)
            except (TypeError, ValueError):
                errors.append(msg_void_or_ip_address.new(path="ip_address"))

        # User agents contain spaces, so they are trimmed rather than dense.
        if is_present(self.user_agent) and not (
            is_trimmed_str(self.user_agent) and self.user_agent.strip()
        ):
            errors.append(msg_void_or_user_agent.new(path="user_agent"))

        return errors
