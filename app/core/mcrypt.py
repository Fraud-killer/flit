import json
from core.config import Config
from cryptography.fernet import Fernet


fernet = Fernet(Config.mcrypt_key.encode())


def encrypt(value):
    json_string = json.dumps(value)
    json_string_bytes = json_string.encode()
    encrypted_bytes = fernet.encrypt(json_string_bytes)
    encrypted = encrypted_bytes.decode()
    return encrypted


def decrypt(encrypted):
    encrypted_bytes = encrypted.encode()
    json_string_bytes = fernet.decrypt(encrypted_bytes)
    json_string = json_string_bytes.decode()
    value = json.loads(json_string)
    return value
