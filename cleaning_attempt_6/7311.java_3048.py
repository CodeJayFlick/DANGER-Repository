import io.BytesIO as BytesIO
from typing import Union

class Apple8900Decryptor:
    def __init__(self):
        pass

    def isValid(self, provider: bytes) -> bool:
        return provider[:4] == b'\x89\x90\x00\x01'

    def decrypt(self, firmware_name: str, firmware_path: str, provider: bytes, monitor=None) -> Union[bytes, None]:
        reader = BinaryReader(provider)
        
        header = Apple8900Header(reader)

        if not header.get_magic().encode() == b'\x89\x90\x00\x01':
            raise Exception("The 8900 file is not valid!")

        encrypted_block = reader.read_next_byte_array(header.size_of_data())

        if header.is_encrypted():
            crypto = iOS_AES_Crypto(Apple8900Constants.AES_KEY_BYTES, Apple8900Constants.AES_IV_ZERO_BYTES)
            
            decrypted_block = crypto.decrypt(encrypted_block)

            return BytesIO(decrypted_block).getvalue()
        
        return BytesIO(encrypted_block).getvalue()

class BinaryReader:
    def __init__(self, provider: bytes):
        self.provider = provider

    def read_bytes(self, offset: int, length: int) -> bytes:
        return self.provider[offset:offset+length]

    def read_next_byte_array(self, size: int) -> bytes:
        return self.read_bytes(0, size)

class Apple8900Header:
    def __init__(self, reader):
        self.reader = reader

    def get_magic(self) -> str:
        return '89 90 00 01'

    def is_encrypted(self) -> bool:
        return True

    def size_of_data(self) -> int:
        return 0
