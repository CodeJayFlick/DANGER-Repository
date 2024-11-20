import hashlib
import hmac

class iOS_Sha1Crypto:
    CRYPTO_ALGORITHM = "HmacSHA1"

    def __init__(self, key):
        self.mac_key = bytes(key)
        try:
            self.mac = hmac.new(self.mac_key, digestmod=hashlib.sha1)
        except Exception as e:
            raise ValueError(f"Error initializing HMAC: {e}")

    def update(self, data):
        self.mac.update(data)

    def encrypt(self, plain_text):
        # Not implemented in the original Java code
        return None

    def decrypt(self, cipher_text=None):
        try:
            if cipher_text is not None:
                return self.mac.digest(cipher_text)
            else:
                return self.mac.digest()
        except Exception as e:
            raise ValueError(f"Error decrypting: {e}")

# Example usage:
key = b"ThisIsMySecretKey"
crypto = iOS_Sha1Crypto(key)

plain_text = b"Hello, World!"
cipher_text = crypto.update(plain_text)
print(cipher_text)  # Output: the encrypted data

decrypted_data = crypto.decrypt()
print(decrypted_data)  # Output: the decrypted data
