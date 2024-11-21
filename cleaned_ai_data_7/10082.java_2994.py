import os
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from base64 import b64decode
from io import StringIO

class SSHKeyManager:
    private_key_password_provider = None

    def __init__(self):
        pass  # static class--can't create

    @staticmethod
    def set_protected_key_store_password_provider(provider):
        SSHKeyManager.private_key_password_provider = provider

    @staticmethod
    def get_ssh_private_key(private_key_file_path) -> bytes:
        if not os.path.isfile(private_key_file_path):
            raise FileNotFoundError(f"SSH private key file not found: {private_key_file_path}")

        with open(private_key_file_path, 'rb') as f:
            return crypto_serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    @staticmethod
    def get_ssh_public_key(public_key_file_path) -> bytes:
        if not os.path.isfile(public_key_file_path):
            raise FileNotFoundError(f"SSH public key file not found: {public_key_file_path}")

        with open(public_key_file_path, 'r') as f:
            lines = [line.strip() for line in f.readlines()]
            ssh_public_key_line = next((line for line in lines if line.startswith("ssh-")), None)
            if ssh_public_key_line is not None:
                pieces = ssh_public_key_line.split()
                if len(pieces) >= 2 and "ssh-rsa" == pieces[0]:
                    return b64decode(pieces[1].encode()).decode().encode()
                elif "ssh-dss" == pieces[0]:
                    return b64decode(pieces[1].encode()).decode().encode()

        raise ValueError(f"Invalid SSH public key file, valid ssh-rsa or ssh-dss entry not found: {public_key_file_path}")
