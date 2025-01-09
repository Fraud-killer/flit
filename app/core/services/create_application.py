from os import urandom
from core import mcrypt
from core.models import Application
from core.services.fingerprint import CreatePublicKey
from core.checks.applications import is_app_visit_sdk_key


class InvalidAppDeviceSdkKey(Exception):
    pass


class CreateApplication:
    @classmethod
    def call(cls, *, name, organization):
        secret_key = str(urandom(15).hex())

        application = Application(
            name=name,
            organization=organization,
            secret_key=mcrypt.encrypt(secret_key),
        )

        application.full_clean()

        public_key = CreatePublicKey.call(application.name)
        visit_sdk_key = dict(public_key)

        if not is_app_visit_sdk_key(visit_sdk_key):
            raise InvalidAppDeviceSdkKey(visit_sdk_key)

        application.visit_sdk_key = mcrypt.encrypt(visit_sdk_key)

        application.save()

        return application
