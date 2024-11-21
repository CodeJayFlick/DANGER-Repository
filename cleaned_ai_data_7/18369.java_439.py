import unittest
from io import BytesIO
from typing import List

class DictionaryDecoderTest(unittest.TestCase):
    def setUp(self):
        self.encoder = None
        self.decoder = None
        self.baos = BytesIO()

    def test_single(self):
        self.test_all(["a", "b", "c"])

    def test_all_unique(self):
        self.test_all(["a", "b", "c"], ["x", "o", "q"], [".", ",", "e", "b", "c"])
        self.test_all([".", ",", "e", "b", "c"])
        self.test_all(["a", "a", "a"])

    def test_all_same(self):
        self.test_all(["a", "a", "a"])
        self.test_all(["b", "b", "b"])

    def test_mixed(self):
        all_chars = [chr(i) + chr(i) + chr(i) for i in range(256)]
        self.test_all(all_chars)

    def test_all(self, *args: List[str]):
        for s in args:
            if not isinstance(s, str):
                raise TypeError("All arguments must be strings")
            self.encoder.encode(BytesIO(s.encode()), self.baos)
        self.encoder.flush()

        out = BytesIO(self.baos.getvalue())
        out.seek(0)

        for s in args:
            while True:
                try:
                    if not self.decoder.has_next(out):
                        break
                    self.assertEqual(s, self.decoder.read_binary(out).decode("utf-8"))
                except Exception as e:
                    print(f"Error: {e}")
                    raise

        self.decoder.reset()
        self.baos.seek(0)

if __name__ == "__main__":
    unittest.main()
