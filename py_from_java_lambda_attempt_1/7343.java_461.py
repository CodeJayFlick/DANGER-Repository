Here is the translation of the Java code to Python:

```Python
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from io import BytesIO

class iOS_AES_Crypto:
    CRYPTO_ALGORITHM = "AES"
    CRYPTO_TRANSFORMATION_CBC = "AES/CBC/NoPadding"

    def __init__(self, key: bytes, iv: bytes):
        if not key or not iv:
            raise ValueError("KEY and IV must be specified")
        
        self.key_length = len(key) * 8
        self.key = key
        self.iv = iv

    def encrypt(self, plain_text: bytes) -> bytes:
        # This method is currently unimplemented in the original Java code.
        return b""

    def decrypt(self, cipher_text: bytes) -> bytes:
        try:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
            encryptor = cipher.encryptor()
            decrypted_bytes = BytesIO(encryptor.update(cipher_text))
            if len(decrypted_bytes.getvalue()) < len(cipher_text):
                raise ValueError("Invalid decryption")
            return decrypted_bytes.getvalue()
        except Exception as e:
            raise ValueError(f"Error decrypting: {str(e)}")

    def update(self, data: bytes) -> None:
        # This method is currently unimplemented in the original Java code.
        pass
```

Please note that this Python translation does not include all the error handling and checks present in the original Java code. It also assumes that you have installed the `cryptography` library which provides cryptographic primitives such as AES encryption/decryption.