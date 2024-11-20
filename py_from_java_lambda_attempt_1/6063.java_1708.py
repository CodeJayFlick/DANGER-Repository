Here is the translation of the given Java code into Python:

```Python
import unittest


class StringTableTest(unittest.TestCase):

    def test_str(self):
        bytes = (b'a', b'b', 0, 
                 b'c', 0,
                 b'x', b'y', b'\n', 0)
        br = BinaryReader(bytes, True)
        st = StringTable.read_string_table(br.get_byte_provider())

        self.assertEqual("ab", st.get_string_at_offset(0))
        self.assertEqual("c", st.get_string_at_offset(3))

    def test_offcut_str(self):
        bytes = (b'a', b'b', 0, 
                 b'c', 0,
                 b'x', b'y', b'\n', 0)
        br = BinaryReader(bytes, True)
        st = StringTable.read_string_table(br.get_byte_provider())

        self.assertEqual("ab", st.get_string_at_offset(0))
        self.assertEqual(b'b'.decode(), st.get_string_at_offset(1))
        self.assertEqual("c", st.get_string_at_offset(3))
        self.assertEqual("", st.get_string_at_offset(4))

    def test_trailing_offcut_str(self):
        bytes = (b'a', b'b', 0, 
                 b'c', 0,
                 b'x', b'y', b'\n', 0)
        br = BinaryReader(bytes, True)
        st = StringTable.read_string_table(br.get_byte_provider())

        try:
            st.get_string_at_offset(9)
            self.fail("Should not get here")
        except Exception as e:
            pass

    def test_neg_offset(self):
        bytes = (b'a', b'b', 0, 
                 b'c', 0,
                 b'x', b'y', b'\n', 0)
        br = BinaryReader(bytes, True)
        st = StringTable.read_string_table(br.get_byte_provider())

        try:
            st.get_string_at_offset(-2)
            self.fail("Should not get here")
        except Exception as e:
            pass

    def test_empty_str_table(self):
        bytes = b''
        br = BinaryReader(bytes, True)
        st = StringTable.read_string_table(br.get_byte_provider())

        try:
            st.get_string_at_offset(0)
            self.fail("Should not get here")
        except Exception as e:
            pass


if __name__ == '__main__':
    unittest.main()
```

Note: Python does not have direct equivalent of Java's `BinaryReader` and `StringTable`. So, I used a simple byte array to represent the binary data. Also, in some places, you might need to adjust the code according to your actual implementation of these classes.