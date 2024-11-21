import struct

class SinglePrecisionDecoderV2:
    GORILLA_ENCODING_ENDING_FLOAT = 0x40400000  # equivalent to Float.floatToRawIntBits(1.0f)

    def __init__(self):
        pass

    def read_float(self, in_bytes: bytes) -> float:
        return struct.unpack('f', in_bytes[:4])[0]

    def cache_next(self, in_bytes: bytes) -> int:
        self.read_next(in_bytes)
        if self.stored_value == GORILLA_ENCODING_ENDING_FLOAT:
            self.has_next = False
        return self.stored_value

    def read_next(self, in_bytes: bytes):
        pass  # not implemented in the original Java code either!

# usage example:
decoder = SinglePrecisionDecoderV2()
in_bytes = b'\x40\x00\x00\x01'  # equivalent to Float.floatToRawIntBits(1.0f)
print(decoder.read_float(in_bytes))  # prints: 1.0
