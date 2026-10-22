import logging

from os import urandom
from core import mcrypt
from core.models import Application
from core.services.fingerprint import CreatePublicKey
from core.checks.applications import is_app_visit_sdk_key
from kernel.config import Config


logger = logging.getLogger(__name__)


class InvalidAppDeviceSdkKey(Exception):
    pass


class CreateApplication:
    """
    Create an application and its API credentials.

    Fingerprint is optional. FLIT ships its own browser collector — /v1/collect
    issues `flit_dk_` device keys and needs no third party — so requiring a
    Fingerprint management key here would have meant no merchant could be
    onboarded without a Fingerprint account, which is not a dependency FLIT
    actually has. When the key is configured the application gets a Fingerprint
    public key too; when it is not, or when Fingerprint is unreachable, the
    application is created without one and device identity comes from the FLIT
    collector.
    """

    @classmethod
    def call(cls, *, name, organization, enforcement=None):
        secret_key = str(urandom(15).hex())

        application = Application(
            name=name,
            organization=organization,
            secret_key=mcrypt.encrypt(secret_key),
        )

        if enforcement:
            application.enforcement = enforcement

        application.full_clean()

        visit_sdk_key = cls.fingerprint_key(name)

        if visit_sdk_key is not None:
            application.visit_sdk_key = mcrypt.encrypt(visit_sdk_key)

        application.save()

        return application

    @classmethod
    def fingerprint_enabled(cls):
        """
        Whether this deployment uses Fingerprint. Read through a method, like
        the other optional integrations, so a test or a deployment can turn it
        off without the config being mutable.
        """
        return bool(Config.fingerprint_management_api_key)

    @classmethod
    def fingerprint_key(cls, name):
        """A Fingerprint public key, or None when Fingerprint is not in use."""
        if not cls.fingerprint_enabled():
            return None

        try:
            public_key = CreatePublicKey.call(name)
        except Exception:
            # An outage at Fingerprint must not stop a merchant being
            # onboarded; the FLIT collector covers device identity either way.
            logger.warning(
                "Could not create a Fingerprint key; continuing without one",
                exc_info=True,
            )
            return None

        visit_sdk_key = dict(public_key)

        if not is_app_visit_sdk_key(visit_sdk_key):
            raise InvalidAppDeviceSdkKey(visit_sdk_key)

        return visit_sdk_key
