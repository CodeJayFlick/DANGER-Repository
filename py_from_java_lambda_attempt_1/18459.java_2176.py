Here is the translation of the Java code into Python:

```Python
import unittest
from io import BytesIO
from typing import Any

class ValueChunkWriterTest(unittest.TestCase):

    def test_write1(self):
        value_encoder = PlainEncoder(TSDataType.FLOAT, 0)
        chunk_writer = ValueChunkWriter("s1", CompressionType.UNCOMPRESSED, TSDataType.FLOAT, TSEncoding.PLAIN, value_encoder)

        for time in range(1, 21):
            if time % 4 == 0:
                chunk_writer.write(time, float(time), True)
            else:
                chunk_writer.write(time, float(time), False)

        chunk_writer.seal_current_page()
        
        self.assertEqual(chunk_writer.get_current_chunk_size(), 77L)

    def test_write2(self):
        value_encoder = PlainEncoder(TSDataType.FLOAT, 0)
        chunk_writer = ValueChunkWriter("s1", CompressionType.UNCOMPRESSED, TSDataType.FLOAT, TSEncoding.PLAIN, value_encoder)

        for time in range(1, 21):
            if time % 4 == 0:
                chunk_writer.write(time, float(time), True)
            else:
                chunk_writer.write(time, float(time), False)

        chunk_writer.seal_current_page()

        for time in range(20, 41):
            if time % 4 == 0:
                chunk_writer.write(time, float(time), True)
            else:
                chunk_writer.write(time, float(time), False)

        chunk_writer.seal_current_page()
        
        self.assertEqual(chunk_writer.get_current_chunk_size(), 229L)


if __name__ == '__main__':
    unittest.main()
```

Note: The `PlainEncoder`, `ValueChunkWriter`, and other classes are not provided in the original code, so I assume they exist or can be implemented.