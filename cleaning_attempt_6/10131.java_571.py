import hashlib
import random
import string

class HashUtilities:
    MD5_ALGORITHM = "MD5"
    SHA256_ALGORITHM = "SHA-256"

    SALT_LENGTH = 4

    def __init__(self):
        pass

    @staticmethod
    def get_random_letter_or_digit():
        val = random.randint(0, 61)
        if val < 10:
            return chr(val + ord('0'))
        elif val < 36:
            return chr(val - 10 + ord('A'))
        else:
            return chr(val - 36 + ord('a'))

    @staticmethod
    def get_hash(algorithm, message):
        return HashUtilities.get_saltied_hash(algorithm, [], message)

    @staticmethod
    def get_saltied_hash(algorithm, salt, message):
        if algorithm == "MD5":
            hash_length = 32
        elif algorithm == "SHA-256":
            hash_length = 64

        msg_bytes = bytearray(salt) + bytearray(message)
        md = hashlib.new(algorithm)

        for i in range(len(msg_bytes)):
            md.update(msg_bytes[i].to_bytes(1, 'big'))

        salted_hash = bytearray(hashlib.sha256(md.digest()).digest())[:hash_length] + bytearray(salt)[:SALT_LENGTH]
        return [chr(x) for x in salted_hash]

    @staticmethod
    def get_saltied_hash(algorithm, message):
        salt = [HashUtilities.get_random_letter_or_digit() for _ in range(4)]
        return HashUtilities.get_saltied_hash(algorithm, bytearray(salt), message)

    @staticmethod
    def get_hash(algorithm, file_path):
        try:
            with open(file_path, 'rb') as f:
                md = hashlib.new(algorithm)
                while True:
                    chunk = f.read(16 * 1024)
                    if not chunk:
                        break
                    md.update(chunk)

                return HashUtilities.convert_bytes_to_string(md.digest())
        except Exception as e:
            print(f"Error: {e}")
            return None

    @staticmethod
    def convert_bytes_to_string(data):
        return ''.join([f"{x:02X}" for x in data])
