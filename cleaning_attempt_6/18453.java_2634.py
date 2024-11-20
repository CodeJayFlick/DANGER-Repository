import unittest
from io import BytesIO, StringIO
import struct

class MeasurementSchemaSerializeTest(unittest.TestCase):

    def test_deserialize_from_bytebuffer(self):
        standard = {'name': 'sensor_1', 'data_type': 0, 'encoding': 2}
        byte_buffer = bytes(struct.pack('10si', len(standard), *list(standard.values())))
        measurement_schema = UnaryMeasurementSchema.deserialize_from(byte_buffer)
        self.assertEqual(measurement_schema, standard)

    def test_deserialize_from_inputstream(self):
        standard = {'name': 'sensor_1', 'data_type': 0, 'encoding': 2}
        byte_buffer = bytes(struct.pack('10si', len(standard), *list(standard.values())))
        input_stream = BytesIO(byte_buffer)
        measurement_schema = UnaryMeasurementSchema.deserialize_from(input_stream)
        self.assertEqual(measurement_schema, standard)

class UnaryMeasurementSchema:
    @classmethod
    def deserialize_from(cls, byte_buffer):
        data_type = struct.unpack('i', byte_buffer[:4])[0]
        encoding = struct.unpack('i', byte_buffer[4:8])[0]
        name_length = struct.unpack('i', byte_buffer[8:12])[0]
        name = byte_buffer[12:12+name_length].decode().strip('\x00')
        return {'name': name, 'data_type': data_type, 'encoding': encoding}

if __name__ == '__main__':
    unittest.main()
