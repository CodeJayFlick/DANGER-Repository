Here is the translation of the Java code to Python:

```Python
import hashlib
import base64
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa


class SSHSignatureCallback:
    def __init__(self, token: bytes, server_signature: bytes):
        self.token = token
        self.server_signature = server_signature
        self.signature = None

    @property
    def token(self) -> bytes:
        return self._token if self._token is not None else None

    @token.setter
    def token(self, value: bytes):
        self._token = value

    @property
    def signature(self) -> bytes:
        return self._signature if self._signature is not None else None

    @signature.setter
    def signature(self, value: bytes):
        self._signature = value

    @property
    def server_signature(self) -> bytes:
        return self.server_signature

    def get_token(self) -> bytes:
        return self.token.copy() if self.token is not None else None

    def get_server_signature(self) -> bytes:
        return self.server_signature

    def is_signed(self) -> bool:
        return self.signature is not None


def sign_callback(ssh_private_key: dict, callback: SSHSignatureCallback):
    private_key = crypto_serialization.load_pem_private_key(
        ssh_private_key['key'].encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    if 'rsa' in ssh_private_key:
        rsa_signature = private_key.public_key().signature_hash(
            callback.token, hashlib.sha1
        )
        signature = base64.b64encode(rsa_signature).decode('utf-8')
        callback.signature = signature.encode('utf-8')

    elif 'dsa' in ssh_private_key:
        random_generator = default_backend().generate_random_bytes(20)
        dsa_signature = private_key.public_key().signature_hash(
            callback.token, hashlib.sha1
        )
        signature = base64.b64encode(dsa_signature).decode('utf-8')
        callback.signature = signature.encode('utf-8')

    else:
        raise ValueError("Unsupported SSH private key")
```

This Python code is a direct translation of the Java code. It uses the `cryptography` library to handle cryptographic operations, and it assumes that the input data (the token) will be provided as bytes objects.