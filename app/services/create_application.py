from os import urandom
from kernel.mcrypt import encrypt
from core.models import Application
from services.fingerprint import CreatePublicKey
from core.checks.applications import is_app_device_sdk_key


class InvalidAppDeviceSdkKey(Exception):
    pass


class CreateApplication:
    @classmethod
    def call(cls, *, name, organization):
        secret_key = str(urandom(30).hex())

        application = Application(
            name=name,
            organization=organization,
            secret_key=encrypt(secret_key),
        )

        application.full_clean()

        public_key = CreatePublicKey.call(application.name)
        device_sdk_key = dict(public_key)

        if not is_app_device_sdk_key(device_sdk_key):
            raise InvalidAppDeviceSdkKey(device_sdk_key)

        application.device_sdk_key = encrypt(device_sdk_key)

        application.save()

        return application
