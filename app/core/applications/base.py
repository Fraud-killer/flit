from os import urandom
from core.mcrypt import encrypt


def generate_secret_key():
    return str(urandom(30).hex())


def generate_encrypted_secret_key():
    return encrypt(generate_secret_key())
