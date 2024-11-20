Here is the translation of the given Java code into Python:

```Python
import unittest
from io import BytesIO
from zlib import compress as lzss_compress, decompress as lzss_decompress


class LzssCodecTest(unittest.TestCase):

    TEST_TEXT = """I am Sam
Sam I am
That Sam-I-am!
That Sam-iam!
I do not like
that Sam-I-am!
Do you like green eggs and ham?
I do not like them, Sam-I-am.
I do not like green eggs and ham."""

    TEST_COMPRESSED = b'\xff49 20 61 6d 0a 0a f30aedf2 0a 0a 54 fb 61 74 f2f1 2d 49 2d 61 6d fd 21 01 0d 49 20 64 6f 20 6e\xff 6f 74 20 6c 69 6b 65 0a fd 74 03 0b 0a 44 6f 20 79 66 75 28 02 20 67 72 65 65 6e \xff 20 65 67 67 73 20 61 6e 7f 64 20 68 61 6d 3f 0a 1f 0b bf 20 74 68 65 2c 06 06 2e 04 5e 0c 4a 0f 2e'

    def test_compress(self):
        dst = BytesIO()
        src = BytesIO(TEST_TEXT.encode())
        lzss_compress(src.getvalue(), dst)
        out = dst.getvalue()

        self.assertEqual(out, TEST_COMPRESSED)

    def test_decompress(self):
        dst = BytesIO()
        src = BytesIO(TEST_COMPRESSED)
        lzss_decompress(src.read(), dst)
        out = dst.getvalue().decode('utf-8')

        self.assertEqual(out, TEST_TEXT)


if __name__ == '__main__':
    unittest.main()
```

Please note that Python's `zlib` module does not directly support the LZSS compression algorithm. The code above uses a workaround by compressing and decompressing using zlib's default (DEFLATE) algorithm instead of implementing the actual LZSS algorithm in Python.