from devkit.checks import is_present, is_dense_str
from devkit.messages import msg_dense_string, msg_void_or_dense_string, msg_in_choices

from .base_event import BaseEvent


class AuthenticationEvent(BaseEvent):
    """
    Something happening to an account's credentials — a login, a reset, a
    second factor coming off, a contact detail changing.

    FLIT had no event for this. Registration and transaction covered the two
    ends of an account's life, and everything in between — the part a
    takeover actually happens in — arrived only as a side effect on a later
    transaction, if at all. On 20 October 2026 an actor took eighteen live
    accounts on a card issuer by requesting a password reset and logging in
    six to thirty seconds later, through two-factor, from a hosting provider,
    with `python-requests`. Every one of those facts was visible to the
    merchant's login handler, and none of them had anywhere to go.

    This is where they go. The merchant reports each credential action as it
    happens; the rules read the sequence back.
    """

    event_type = "authentication"

    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    PASSWORD_CHANGE = "password_change"
    EMAIL_CHANGE = "email_change"
    PHONE_CHANGE = "phone_change"
    TWO_FACTOR_ENABLED = "two_factor_enabled"
    TWO_FACTOR_DISABLED = "two_factor_disabled"
    NEW_DEVICE_LOGIN = "new_device_login"

    ACTIONS = (
        LOGIN,
        LOGIN_FAILED,
        PASSWORD_RESET_REQUESTED,
        PASSWORD_RESET_COMPLETED,
        PASSWORD_CHANGE,
        EMAIL_CHANGE,
        PHONE_CHANGE,
        TWO_FACTOR_ENABLED,
        TWO_FACTOR_DISABLED,
        NEW_DEVICE_LOGIN,
    )

    # Actions that recover or replace a credential. These are how a takeover
    # gets in.
    RESET_ACTIONS = (PASSWORD_RESET_REQUESTED, PASSWORD_RESET_COMPLETED)

    # Actions that change what the account is tied to. These are how a
    # takeover keeps the account once it is in.
    MANIPULATION_ACTIONS = (
        PASSWORD_CHANGE,
        EMAIL_CHANGE,
        PHONE_CHANGE,
        TWO_FACTOR_DISABLED,
    )

    # Every action an attacker has to perform to turn a reset into money.
    CREDENTIAL_ACTIONS = (LOGIN,) + RESET_ACTIONS + MANIPULATION_ACTIONS

    attributes = [
        "id",
        "client_id",
        "visit_id",
        "visit_token",
        "ip_address",
        "user_agent",
        "action",
        # "success" or "failure". Optional; a login that reached the handler
        # at all is usually a success, a `login_failed` never is.
        "status",
        # How the credential was presented: "password", "google", "apple",
        # "token". Lets a rule tell a social sign-in from a typed password.
        "auth_method",
        # Whether a second factor was demanded and passed on this action. A
        # takeover that clears it from a scripted client is a different
        # finding from one that never met it.
        "second_factor",
    ]

    def verify(self, policy=None):
        errors = list()

        if not is_dense_str(self.id):
            errors.append(msg_dense_string.new(path="id"))

        if not is_dense_str(self.client_id):
            errors.append(msg_dense_string.new(path="client_id"))

        if not is_dense_str(self.action):
            errors.append(msg_dense_string.new(path="action"))
        elif self.action not in self.ACTIONS:
            errors.append(
                msg_in_choices.new(path="action", context=dict(choices=list(self.ACTIONS)))
            )

        for name in ("visit_id", "status", "auth_method"):
            value = getattr(self, name)
            if is_present(value) and not is_dense_str(value):
                errors.append(msg_void_or_dense_string.new(path=name))

        errors.extend(self.verify_visit_attrs())
        errors.extend(self.verify_network_attrs())

        return errors

    @property
    def is_credential_action(self):
        return self.action in self.CREDENTIAL_ACTIONS

    @property
    def is_reset(self):
        return self.action in self.RESET_ACTIONS

    @property
    def is_manipulation(self):
        return self.action in self.MANIPULATION_ACTIONS

    @property
    def succeeded(self):
        status = getattr(self, "status", None)
        if is_present(status):
            return str(status).lower() in ("success", "succeeded", "ok", "true")
        return self.action != self.LOGIN_FAILED
