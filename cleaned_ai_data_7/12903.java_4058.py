import unittest
from binascii import hexlify

class AbstractOpBehaviorTest:
    def __init__(self):
        pass

    @staticmethod
    def assert_equal(expected, result, byte_size):
        expected_bytes = bytes(result.to_bytes(byte_size, 'big'))
        actual_bytes = bytes(result.to_bytes(byte_size, 'big'))
        unittest.TestCase().assertEqual(hexlify(expected_bytes).decode('utf-8'), hexlify(actual_bytes).decode('utf-8'))

    @staticmethod
    def to_hex_string(bytes):
        return "0x" + "".join(f"{b:02X}" for b in bytes)

    @staticmethod
    def get_unsigned_big_int(val, size=8):
        if val > 0:
            return val
        else:
            return int.from_bytes(val.to_bytes(size, 'big'), byteorder='big')

if __name__ == "__main__":
    unittest.main()
