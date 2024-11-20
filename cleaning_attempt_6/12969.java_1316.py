import unittest

class EnumDataTypeTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_negative_value(self):
        enum_dt = EnumDataType("Test", 4)
        enum_dt.add("bob", -1)

        mem_buffer = ByteMemBufferImpl(Address.NO_ADDRESS, bytes([0xFF]), True)
        self.assertEqual(enum_dt.get_representation(mem_buffer, None, 0), "bob")

    def test_upper_bit_long_value(self):
        enum_dt = EnumDataType("Test", 4)
        enum_dt.add("bob", 2**31 - 1)

        mem_buffer = ByteMemBufferImpl(Address.NO_ADDRESS, bytes([0x80]), True)
        self.assertEqual(enum_dt.get_representation(mem_buffer, None, 0), "bob")

if __name__ == "__main__":
    unittest.main()
