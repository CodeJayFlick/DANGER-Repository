Here is the translation of the Java code into Python:

```Python
import unittest
from io import BytesIO

class PageWriterTest(unittest.TestCase):

    def testWriteInt(self):
        writer = PageWriter()
        writer.set_time_encoder(PlainEncoder(TSDataType.INT64, 0))
        writer.set_value_encoder(PlainEncoder(TSDataType.INT32, 0))
        writer.init_statistics(TSDataType.INT32)
        value = 1
        time_count = 0
        try:
            writer.write(time_count, value)
            self.assertEqual(writer.estimate_max_mem_size(), 9)
            buffer1 = BytesIO()
            buffer2 = BytesIO(buffer1.getvalue())
            writer.reset(UnaryMeasurementSchema("s0", TSDataType.INT32, TSEncoding.RLE))
            time_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer2)
            time_bytes = bytearray(time_size)
            buffer2.readinto(time_bytes)
            decoder = PlainDecoder()
            for i in range(time_count):
                self.assertEqual(i, decoder.read_long(BytesIO(bytearray([time_bytes[i]]))))
            self.assertEqual(value, decoder.read_int(BytesIO(bytearray([buffer1.getvalue()[0]]))))

        except Exception as e:
            self.fail()

    def testWriteLong(self):
        writer = PageWriter()
        writer.set_time_encoder(PlainEncoder(TSDataType.INT64, 0))
        writer.set_value_encoder(PlainEncoder(TSDataType.INT64, 0))
        writer.init_statistics(TSDataType.INT64)
        value = 123142120391
        time_count = 0
        try:
            writer.write(time_count, value)
            self.assertEqual(writer.estimate_max_mem_size(), 16)
            buffer1 = BytesIO()
            buffer2 = BytesIO(buffer1.getvalue())
            writer.reset(UnaryMeasurementSchema("s0", TSDataType.INT64, TSEncoding.RLE))
            time_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer2)
            time_bytes = bytearray(time_size)
            buffer2.readinto(time_bytes)
            decoder = PlainDecoder()
            for i in range(time_count):
                self.assertEqual(i, decoder.read_long(BytesIO(bytearray([time_bytes[i]]))))
            self.assertEqual(value, decoder.read_long(BytesIO(bytearray([buffer1.getvalue()[0]]))))

        except Exception as e:
            self.fail()

    def testWriteFloat(self):
        writer = PageWriter()
        writer.set_time_encoder(PlainEncoder(TSDataType.INT64, 0))
        writer.set_value_encoder(PlainEncoder(TSDataType.FLOAT, 0))
        writer.init_statistics(TSDataType.FLOAT)
        value = 2.2
        time_count = 0
        try:
            writer.write(time_count, value)
            self.assertEqual(writer.estimate_max_mem_size(), 12)
            buffer1 = BytesIO()
            buffer2 = BytesIO(buffer1.getvalue())
            writer.reset(UnaryMeasurementSchema("s0", TSDataType.INT64, TSEncoding.RLE))
            time_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer2)
            time_bytes = bytearray(time_size)
            buffer2.readinto(time_bytes)
            decoder = PlainDecoder()
            for i in range(time_count):
                self.assertEqual(i, decoder.read_long(BytesIO(bytearray([time_bytes[i]]))))
            self.assertAlmostEqual(value, decoder.read_float(BytesIO(bytearray([buffer1.getvalue()[0]]))), delta=TestConstant.float_min_delta)

        except Exception as e:
            self.fail()

    def testWriteBoolean(self):
        writer = PageWriter()
        writer.set_time_encoder(PlainEncoder(TSDataType.INT64, 0))
        writer.set_value_encoder(PlainEncoder(TSDataType.BOOLEAN, 0))
        writer.init_statistics(TSDataType.BOOLEAN)
        value = False
        time_count = 0
        try:
            writer.write(time_count, value)
            self.assertEqual(writer.estimate_max_mem_size(), 9)
            buffer1 = BytesIO()
            buffer2 = BytesIO(buffer1.getvalue())
            writer.reset(UnaryMeasurementSchema("s0", TSDataType.INT64, TSEncoding.RLE))
            time_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer2)
            time_bytes = bytearray(time_size)
            buffer2.readinto(time_bytes)
            decoder = PlainDecoder()
            for i in range(time_count):
                self.assertEqual(i, decoder.read_long(BytesIO(bytearray([time_bytes[i]]))))
            self.assertEqual(value, decoder.read_boolean(BytesIO(bytearray([buffer1.getvalue()[0]]))))

        except Exception as e:
            self.fail()

    def testWriteBinary(self):
        writer = PageWriter()
        writer.set_time_encoder(PlainEncoder(TSDataType.INT64, 0))
        writer.set_value_encoder(PlainEncoder(TSDataType.TEXT, 0))
        writer.init_statistics(TSDataType.TEXT)
        value = "I have a dream"
        time_count = 0
        try:
            writer.write(time_count, Binary(value))
            self.assertEqual(writer.estimate_max_mem_size(), 23)
            buffer1 = BytesIO()
            buffer2 = BytesIO(buffer1.getvalue())
            writer.reset(UnaryMeasurementSchema("s0", TSDataType.INT64, TSEncoding.RLE))
            time_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer2)
            time_bytes = bytearray(time_size)
            buffer2.readinto(time_bytes)
            decoder = PlainDecoder()
            for i in range(time_count):
                self.assertEqual(i, decoder.read_long(BytesIO(bytearray([time_bytes[i]]))))
            self.assertEqual(value, decoder.read_binary(BytesIO(bytearray([buffer1.getvalue()[0]]))).get_string_value())

        except Exception as e:
            self.fail()

    def testWriteDouble(self):
        writer = PageWriter()
        writer.set_time_encoder(PlainEncoder(TSDataType.INT64, 0))
        writer.set_value_encoder(PlainEncoder(TSDataType.DOUBLE, 0))
        writer.init_statistics(TSDataType.DOUBLE)
        value = 1.0
        time_count = 0
        try:
            writer.write(time_count, value)
            self.assertEqual(writer.estimate_max_mem_size(), 16)
            buffer1 = BytesIO()
            buffer2 = BytesIO(buffer1.getvalue())
            writer.reset(UnaryMeasurementSchema("s0", TSDataType.INT64, TSEncoding.RLE))
            time_size = ReadWriteForEncodingUtils.read_unsigned_var_int(buffer2)
            time_bytes = bytearray(time_size)
            buffer2.readinto(time_bytes)
            decoder = PlainDecoder()
            for i in range(time_count):
                self.assertEqual(i, decoder.read_long(BytesIO(bytearray([time_bytes[i]]))))
            self.assertAlmostEqual(value, decoder.read_double(BytesIO(bytearray([buffer1.getvalue()[0]]])), delta=0)

        except Exception as e:
            self.fail()

if __name__ == '__main__':
    unittest.main()
```

Note: This code assumes that the Java classes `PageWriter`, `PlainEncoder`, `TSDataType`, and others are equivalent in Python.