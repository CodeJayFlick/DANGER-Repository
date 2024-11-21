import base64
import os
from Crypto.Cipher import AES, CBC
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2HMAC
from hashlib import sha256

class Crypto:
    OPENSSL_SALTED_TEXT = "Salted__".encode('utf-8')
    SALT_LENGTH = 8
    KEY_LENGTH = 32
    IV_LENGTH = 16
    NUMBER_OF_ITERATIONS = 1024

    def get_aes_password_key(self, password: bytes, salt: bytes) -> tuple:
        kdf = PBKDF2HMAC(
            algorithm=sha256,
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.NUMBER_OF_ITERATIONS
        )
        key = kdf.derive(password)
        return (key[:self.KEY_LENGTH], get_random_bytes(self.IV_LENGTH))

    def encrypt(self, plain_text: bytes, password: bytes) -> str:
        salt = os.urandom(self.SALT_LENGTH)
        key, iv = self.get_aes_password_key(password, salt)

        cipher = AES.new(key, CBC(iv))
        encrypted_data = pad(plain_text, block_size=16)
        decrypted_data = cipher.encrypt(encrypted_data)

        return base64.b64encode(salt + decrypted_data).decode('utf-8')

    def decrypt(self, text_to_decode: str) -> bytes:
        decoded_bytes = base64.b64decode(text_to_decode.encode('utf-8'))
        salt = decoded_bytes[:self.SALT_LENGTH]
        cipher_text = decoded_bytes[self.SALT_LENGTH:]

        key, iv = self.get_aes_password_key(decoded_bytes[:16], salt)
        cipher = AES.new(key, CBC(iv))
        decrypted_data = unpad(cipher.decrypt(cipher_text), block_size=16)

        return decrypted_data
