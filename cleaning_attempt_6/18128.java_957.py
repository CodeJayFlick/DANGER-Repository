import struct

class DoublePrecisionDecoderV2:
    GORILLA_ENCODING_ENDING_DOUBLE = 4.0

    def __init__(self):
        self.GORILLA_ENCODING_ENDING = struct.unpack('<Q', struct.pack('<d', self.GORILLA_ENCODING_ENDING_DOUBLE))[0]

    def read_double(self, in_bytes: bytes) -> float:
        return struct.unpack('<d', in_bytes[:8])[0]

    def cache_next(self, in_bytes: bytes) -> int:
        self.read_next(in_bytes)
        if self.stored_value == self.GORILLA_ENCODING_ENDING:
            self.has_next = False
        return self.stored_value

    def read_next(self, in_bytes: bytes):
        # implement me!
        pass

# usage example
decoder = DoublePrecisionDecoderV2()
in_bytes = b'\x00\x01\x02\x03\x04\x05\x06\x07'
print(decoder.read_double(in_bytes))  # prints the double value read from the byte buffer
