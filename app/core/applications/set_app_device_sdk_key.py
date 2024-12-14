from core.applications.mezages import (
    mzg_app_device_sdk_key,
    mzg_app_has_device_sdk_key,
)

from core.fingerprint import Fingerprint
from kernel.mcrypt import encrypt, decrypt
from core.applications.checks import is_app_device_sdk_key
from core.applications.exceptions import AppHasDeviceSdkKeyError


class SetAppDeviceSdkKeyError(Exception):
    pass


class SetAppDeviceSdkKey:
    @classmethod
    def exec(cls, **kwargs):
        return cls(**kwargs).call()

    def __init__(self, *, application, reset=False):
        self.reset = reset
        self.application = application

    def call(self):
        prev_device_sdk_key = self.application.device_sdk_key

        if not self.reset and prev_device_sdk_key:
            raise AppHasDeviceSdkKeyError(mzg_app_has_device_sdk_key.text)

        if prev_device_sdk_key:
            prev_device_sdk_key_data = decrypt(prev_device_sdk_key)
            prev_public_key_id = prev_device_sdk_key_data["id"]
            Fingerprint.delete_public_key(prev_public_key_id)

        device_sdk_key = Fingerprint.create_public_key(self.application.name)

        if not is_app_device_sdk_key(device_sdk_key):
            raise SetAppDeviceSdkKeyError(mzg_app_device_sdk_key.text)

        self.application.device_sdk_key = encrypt(device_sdk_key)
        self.application.full_clean()
        self.application.save()

        return device_sdk_key["token"]
