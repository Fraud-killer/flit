from .client_event import ClientEvent as ClientEvent
from .transaction_event import TransactionEvent as TransactionEvent
from .registration_event import RegistrationEvent as RegistrationEvent
from .authentication_event import AuthenticationEvent as AuthenticationEvent


# Every event that carries client, device and network signals rather than
# money. Rules that reason about who is acting — bot and IP intelligence,
# device integrity, the identity graph — gate on this rather than listing
# event types themselves, so a new event type cannot silently skip them.
SIGNAL_EVENTS = (ClientEvent, TransactionEvent, RegistrationEvent, AuthenticationEvent)
