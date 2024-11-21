Here is the translation of the given Java code into Python:

```Python
import unittest
from io import BytesIO, StringIO
import struct

class ReadWriteStreamUtilsTest(unittest.TestCase):

    def setUp(self):
        self.uint_list = []
        self.int_le_list = []
        self.long_le_list = []

        uv_int = 123
        for _ in range(10):
            self.uint_list.append(uv_int)
            self.uint_list.append(uv_int - 1)
            uv_int *= 3

        le_int = 17
        for _ in range(17):
            self.int_le_list.append(le_int)
            self.int_le_list.append(le_int - 1)
            le_int *= 3

        le_long = 13
        for _ in range(38):
            self.long_le_list.append(le_long)
            self.long_le_list.append(le_long - 1)
            le_long *= 3

    def test_get_max_bit_width(self):
        uv_int_list = []
        uv_int_list.append(0)
        self.assertEqual(ReadWriteStreamUtils.get_max_bit_width(uv_int_list), 1)

        uv_int_list.append(1)
        self.assertEqual(ReadWriteStreamUtils.get_max_bit_width(uv_int_list), 1)

        for _ in range(10):
            uv_int = 123
            uv_int_list.extend([uv_int, uv_int - 1])
            uv_int *= 3

    def test_read_unsigned_varint(self):
        for uvarint in self.uint_list:
            baos = BytesIO()
            ReadWriteStreamUtils.write_unsigned_varint(uvarint, baos)
            bais = BytesIO(baos.getvalue())
            value_read = ReadWriteStreamUtils.read_unsigned_varint(bais)
            self.assertEqual(value_read, uvarint)

    def test_write_unsigned_varint(self):
        pass

    def test_write_int_little_endian_padded_on_bit_width(self):
        pass

    def test_write_long_little_endian_padded_on_bit_width(self):
        pass

    def test_read_int_little_endian_padded_on_bit_width(self):
        for value in self.int_le_list:
            bitwidth = 32 - value.bit_length()
            baos = BytesIO()
            ReadWriteStreamUtils.write_int_little_endian_padded_on_bit_width(value, baos, bitwidth)
            buffer = memoryview(baos.getvalue())

            value_read = struct.unpack('<i', buffer[:4])[0]
            self.assertEqual(value_read, value)

    def test_read_long_little_endian_padded_on_bit_width(self):
        for value in self.long_le_list:
            bitwidth = 64 - value.bit_length()
            baos = BytesIO()
            ReadWriteStreamUtils.write_long_little_endian_padded_on_bit_width(value, baos, bitwidth)
            buffer = memoryview(baos.getvalue())

            value_read = struct.unpack('<q', buffer[:8])[0]
            self.assertEqual(value_read, value)

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Before`, `@After` and JUnit testing framework. Instead, you can use the built-in `unittest` module to write unit tests in Python.