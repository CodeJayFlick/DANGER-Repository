import struct
import hashlib

class CliSigAssembly:
    def __init__(self, blob):
        self.sha1_hash = bytearray(20)
        self.bit_length = None
        self.public_exponent = None
        self.public_key_signature = bytearray()

        if not hasattr(blob, 'get_contents_reader'):
            return

        reader = blob.get_contents_reader()
        self.sha1_hash = reader.read_next_bytes(20)

        magic_value = reader.read_next_int()
        if magic_value != 0x31415352:
            print(f"An Assembly blob was found without the expected RSA1 signature: {blob.name}")
            return

        self.bit_length = reader.read_next_int()
        self.public_exponent = reader.read_next_int()
        self.public_key_signature = reader.read_next_bytes(self.bit_length // 8)

    def get_contents_data_type(self):
        struct = {'sha1': ('B', self.sha1_hash), 'magic': ('I', [0x31415352]), 
                  '_RSAPUBKEY.bitlen': ('i', [self.bit_length]), 
                  '_RSAPUBKEY.pubexp': ('i', [self.public_exponent]), 
                  'pubkey': ('B' * self.bit_length // 8, self.public_key_signature)}
        return struct

    def get_contents_name(self):
        return "AssemblySig"

    def get_contents_comment(self):
        return "Data describing an Assembly signature"

    def get_representation_common(self, stream, is_short=False):
        return f"Assembly:\r\tSHA1: {self.sha1_hash.hex()}\r\tBit length: {self.bit_length}\r\tPublic exponent: {self.public_exponent}\r\tSignature: {self.public_key_signature.hex()}"

# Usage
blob = ...  # your blob object here
assembly = CliSigAssembly(blob)
print(assembly.get_representation_common())
