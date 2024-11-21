Here is the translation of the Java code to Python:

```Python
import logging
from typing import List

class BitmapDecoderTest:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.int_list: List[int] = []
        self.bool_list: List[bool] = []

    def setup(self) -> None:
        self.int_list = [i % 9 for i in range(100000)]
        self.bool_list = [(i % 8 < 4) for i in range(100000)]

    def teardown(self) -> None:
        pass

    def test_bitmap_read_int(self) -> None:
        for _ in range(1, 10):
            self.test_int(self.int_list, False)

    def test_int(self, list: List[int], is_debug: bool, repeat_count: int) -> None:
        baos = bytearray()
        encoder = BitmapEncoder()
        for _ in range(repeat_count):
            for value in list:
                encoder.encode(value, baos)
            encoder.flush(baos)

        bais = bytes(baos)
        decoder = BitmapDecoder()
        for _ in range(repeat_count):
            for value in list:
                value_ = decoder.read_int(bais)
                if is_debug:
                    self.logger.debug(f"{value} // {value_}")
                assert value == value_

if __name__ == "__main__":
    test = BitmapDecoderTest()
    test.setup()
    test.test_bitmap_read_int()
```

Please note that Python does not have direct equivalent of Java's `@Before` and `@After` methods. Instead, you can use the setup method to initialize your variables before running tests.

Also, I used a list comprehension in the `setup` method to generate the lists of integers and booleans.