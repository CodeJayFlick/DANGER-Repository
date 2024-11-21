Here is the equivalent Python code:

```Python
import unittest
from io import BytesIO, StringIO

class ReadWriteToBytesUtilsTest(unittest.TestCase):

    def test_short(self):
        for i in [1, 2, 3, 4, 5]:
            output = BytesIO()
            WriteReadUtils.write(i, output)
            size = len(output.getvalue())
            bytes = output.getvalue()
            input_stream = BytesIO(bytes)
            self.assertEqual(WriteReadUtils.read_short(input_stream), i)

    def test_short2(self):
        for i in [1, 2, 3, 4, 5]:
            buffer = bytearray(2)
            WriteReadUtils.write(i, buffer)
            short_k = WriteReadUtils.read_short(buffer)
            self.assertEqual(i, short_k)

    def test_short3(self):
        for i in [1, 2, 3, 4, 5]:
            output_stream = BytesIO()
            WriteReadUtils.write(i, output_stream)
            size = len(output_stream.getvalue())
            bytes = output_stream.getvalue()
            buffer = bytearray(bytes)
            self.assertEqual(WriteReadUtils.read_short(buffer), i)

if __name__ == '__main__':
    unittest.main()
```

Note: The `ReadWriteIOUtils` class is not provided in the original code, so I assumed it's a custom utility class that provides methods for writing and reading data. In Python, we use built-in modules like `io` to work with file-like objects and byte arrays.