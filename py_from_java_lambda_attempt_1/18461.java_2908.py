Here is the translation of the Java code into Python:

```Python
import unittest
from io import BytesIO

class VectorMeasurementSchemaStub:
    def __init__(self):
        pass

class TestVectorChunkWriterImpl(unittest.TestCase):

    def test_write1(self):
        measurement_schema = VectorMeasurementSchemaStub()
        chunk_writer = VectorChunkWriterImpl(measurement_schema)

        for time in range(1, 21):
            chunk_writer.write(time, float(time), False)
            chunk_writer.write(time, time, False)
            chunk_writer.write(time, double(time), False)
            chunk_writer.write(time)

        chunk_writer.seal_current_page()

        self.assertEqual(528, chunk_writer.get_serialized_chunk_size())

        try:
            test_ts_file_output = TestTsFileOutput()
            writer = TsFileIOWriter(test_ts_file_output, True)
            chunk_writer.write_to_file_writer(writer)
            public_baos = test_ts_file_output.public_baos
            buffer = BytesIO(public_baos.get_buf().tobytes())
            
            # time chunk
            self.assertEqual(0x80 | MetaMarker.ONLY_ONE_PAGE_ CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName", buffer.read_var_int_string())
            self.assertEqual(164, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.VECTOR.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())
            buffer.seek(buffer.tell() + 164)

            # value chunk 1
            self.assertEqual(0x40 | MetaMarker.ONLY_ONE_PAGE_ CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName.s1", buffer.read_var_int_string())
            self.assertEqual(89, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.FLOAT.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())
            buffer.seek(buffer.tell() + 89)

            # value chunk 2
            self.assertEqual(0x40 | MetaMarker.ONLY_ONE_PAGE_ CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName.s2", buffer.read_var_int_string())
            self.assertEqual(29, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.INT32.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())
            buffer.seek(buffer.tell() + 29)

            # value chunk 3
            self.assertEqual(0x40 | MetaMarker.ONLY_ONE_PAGE_ CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName.s3", buffer.read_var_int_string())
            self.assertEqual(171, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.DOUBLE.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())

        except IOException as e:
            print(e)
            self.fail()

    def test_write2(self):
        measurement_schema = VectorMeasurementSchemaStub()
        chunk_writer = VectorChunkWriterImpl(measurement_schema)

        for time in range(1, 21):
            chunk_writer.write(time, float(time), False)
            chunk_writer.write(time, time, False)
            chunk_writer.write(time, double(time), False)
            chunk_writer.write(time)

        chunk_writer.seal_current_page()

        for time in range(21, 41):
            chunk_writer.write(time, float(time), False)
            chunk_writer.write(time, time, False)
            chunk_writer.write(time, double(time), False)
            chunk_writer.write(time)

        chunk_writer.seal_current_page()

        self.assertEqual(1295, chunk_writer.get_serialized_chunk_size())

        try:
            test_ts_file_output = TestTsFileOutput()
            writer = TsFileIOWriter(test_ts_file_output, True)
            chunk_writer.write_to_file_writer(writer)
            public_baos = test_ts_file_output.public_baos
            buffer = BytesIO(public_baos.get_buf().tobytes())
            
            # time chunk
            self.assertEqual(0x80 | MetaMarker.CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName", buffer.read_var_int_string())
            self.assertEqual(362, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.VECTOR.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())
            buffer.seek(buffer.tell() + 362)

            # value chunk 1
            self.assertEqual(0x40 | MetaMarker.CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName.s1", buffer.read_var_int_string())
            self.assertEqual(260, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.FLOAT.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())
            buffer.seek(buffer.tell() + 260)

            # value chunk 2
            self.assertEqual(0x40 | MetaMarker.CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName.s2", buffer.read_var_int_string())
            self.assertEqual(140, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.INT32.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())
            buffer.seek(buffer.tell() + 140)

            # value chunk 2
            self.assertEqual(0x40 | MetaMarker.CHUNK_HEADER, buffer.read1Byte())
            self.assertEqual("vectorName.s3", buffer.read_var_int_string())
            self.assertEqual(456, buffer.read_unsigned_var_int())
            self.assertEqual(TSDataType.DOUBLE.serialize(), buffer.read1Byte())
            self.assertEqual(CompressionType.UNCOMPRESSED.serialize(), buffer.read1Byte())
            self.assertEqual(TSEncoding.PLAIN.serialize(), buffer.read1Byte())

        except IOException as e:
            print(e)
            self.fail()

if __name__ == '__main__':
    unittest.main()
```

Note that this code is a direct translation of the Java code and may not be optimal or idiomatic Python.