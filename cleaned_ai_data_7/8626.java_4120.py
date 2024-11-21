import unittest
from struct import pack, unpack

class NumericTest(unittest.TestCase):

    UNSIGNED_LONG_MAX = int('ffffffffffffffff', 16)
    OCTOWORD_MIN = int('-80000000000000000000000000000000', 16)
    OCTOWORD_MAX = int('7fffffffffffffffffffffff', 16)

    def get_char_byte(self, value):
        if -128 <= value <= 127:
            return pack('<h', value).encode()
        else:
            raise ValueError("Char out of range")

    def get_short_bytes(self, value):
        return pack('<h', value).encode()

    def get_unsigned_short_bytes(self, value):
        if 0 <= value <= 0xffff:
            return pack('<H', value).encode()
        else:
            raise ValueError("Unsigned Short out of range")

    def get_int_bytes(self, value):
        return pack('<i', value).encode()

    def get_unsigned_int_bytes(self, value):
        if 0 <= value <= 0xffffffffL:
            return pack('<I', value).encode()
        else:
            raise ValueError("Unsigned Int out of range")

    def get_long_bytes(self, value):
        return pack('<q', value).encode()

    def get_unsigned_long_bytes(self, value):
        if 0 <= value <= self.UNSIGNED_LONG_MAX:
            return pack('<Q', value).encode()
        else:
            raise ValueError("Unsigned Long out of range")

    def get_octoword_bytes(self, value):
        return pack('<32s', value).encode()

    # Tests
    @unittest.skipIf(True, "Test is not implemented")
    def test_numeric_no_sub_type_zero(self):
        sub_type = 0x0000
        val = 0
        bytes_val = self.get_char_byte(val)
        writer = PdbByteWriter()
        writer.put_bytes(pack('<H', sub_type), len(pack('<H', sub_type)))
        writer.put_bytes(bytes_val, len(bytes_val))
        reader = PdbByteReader(writer.get())
        numeric = Numeric(reader)

    @unittest.skipIf(True, "Test is not implemented")
    def test_numeric_no_sub_type_max(self):
        # ... similar tests for other values ...

if __name__ == '__main__':
    unittest.main()
