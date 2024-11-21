Here is the translation of the given Java code into equivalent Python code:

```Python
import unittest
from typing import List

class PageReaderTest(unittest.TestCase):

    def test_long(self):
        self._test("Long", "Test INT64", LongRleEncoder(), LongRleDecoder(), TSDataType.INT64, 1000000)

    def test_boolean(self):
        self._test("Boolean", "Test Boolean", IntRleEncoder(), IntRleDecoder(), TSDataType.BOOLEAN, 1000000)

    def test_int(self):
        self._test("Int", "Test INT32", IntRleEncoder(), IntRleDecoder(), TSDataType.INT32, 1000000)

    def test_float(self):
        self._test("Float", "Test FLOAT", SinglePrecisionEncoderV1(), SinglePrecisionDecoderV1(), TSDataType.FLOAT, 1000000)
        self._test("Float2", "Test FLOAT", SinglePrecisionEncoderV1(), SinglePrecisionDecoderV1(), TSDataType.FLOAT, 1000000)

    def test_double(self):
        self._test("Double", "Test Double", DoublePrecisionEncoderV1(), DoublePrecisionDecoderV1(), TSDataType.DOUBLE, 1000000)
        self._test("Double2", "Test Double", DoublePrecisionEncoderV1(), DoublePrecisionDecoderV1(), TSDataType.DOUBLE, 1000000)

    def test_binary(self):
        self._test("Binary", "Test Binary", PlainEncoder(TSDataType.TEXT, 1000), PlainDecoder(), TSDataType.TEXT, 1000000)

    def _test(self, name: str, encoder_name: str, encoder: object, decoder: object, data_type: int, count: int):
        try:
            page_writer = PageWriter()
            page_writer.set_time_encoder(DeltaBinaryEncoder.LongDeltaEncoder())
            page_writer.set_value_encoder(encoder)
            page_writer.init_statistics(data_type)
            write_data(page_writer)

            page = ByteBuffer.wrap(page_writer.get_uncompressed_bytes().array())

            page_reader = PageReader(page, data_type, decoder, DeltaBinaryDecoder.LongDeltaDecoder(), None)

            index = 0
            batch_data = page_reader.get_all_satisfied_page_data()
            self.assertIsNotNone(batch_data)

            while batch_data.has_current():
                self.assertEqual(index, int(batch_data.current_time()))
                self.assertEqual(generate_value_by_index(index), batch_data.current_value())
                batch_data.next()
                index += 1

            self.assertEqual(count, index)
        except IOException as e:
            print("Fail when executing test: [" + name + "]")
            self.fail()

    def generate_value_by_index(self, i):
        # Implement your logic here
        pass


class PageReader(unittest.TestCase):

    def test_delete(self):
        try:
            page_writer = PageWriter()
            page_writer.set_time_encoder(DeltaBinaryEncoder.LongDeltaEncoder())
            page_writer.set_value_encoder(LongRleEncoder())
            page_writer.init_statistics(TSDataType.INT64)
            write_data(page_writer)

            page = ByteBuffer.wrap(page_writer.get_uncompressed_bytes().array())

            page_reader = PageReader(page, TSDataType.INT64, LongRleDecoder(), DeltaBinaryDecoder.LongDeltaDecoder(), None)

            index = 0
            delete_intervals: List[TimeRange] = [TimeRange(5, 10), TimeRange(20, 30), TimeRange(50, 70)]
            page_reader.set_delete_interval_list(delete_intervals)
            batch_data = page_reader.get_all_satisfied_page_data()
            self.assertIsNotNone(batch_data)

            for time_range in page_reader.get_delete_interval_list():
                while batch_data.has_current():
                    self.assertEqual(index, int(batch_data.current_time()))
                    self.assertEqual(generate_value_by_index(index), batch_data.current_value())
                    batch_data.next()
                    index += 1
                    if index == time_range.min:
                        index = (time_range.max + 1)
                        break

        except IOException as e:
            print("Fail when executing test: [" + name + "]")
            self.fail()


class TimeRange:

    def __init__(self, min: int, max: int):
        self.min = min
        self.max = max


if __name__ == '__main__':
    unittest.main()
```

Please note that the Python code above is a direct translation of your Java code. However, it might not work as expected because some parts are missing (like `ByteBuffer`, `PageWriter`, etc.) and also there's no implementation for `generate_value_by_index` method which seems to be specific to each test case.

Also, please note that Python does not have a direct equivalent of Java's ByteBuffer. You can use the built-in bytes or bytearray objects instead.