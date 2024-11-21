import numpy as np
from io import BytesIO
import os

class NDSerializerTest:
    def test_nd_serializer(self):
        for file_name in ["0d.npy", "1d.npy", "2d.npy", "boolean.npy", "fp16.npy", "fp32.npy", "int8.npy", "uint8.npy"]:
            with open(os.path.join("src/test/resources/", file_name), 'rb') as f:
                data = np.load(f)
            
            assert data.dtype == {'0d': '<f8', '1d': '<i8', '2d': '<i4', 'boolean': '?',
                                   'fp16': '<f2', 'fp32': '<f4', 'int8': '<i1', 'uint8': '<u1'}.get(file_name)
            
            encoded_data = data.tobytes()
            with BytesIO() as f:
                np.save(f, data)
                assert f.getvalue() == encoded_data

    def encode(self, array):
        return array.tobytes()

    def decode(self, manager, data):
        return np.frombuffer(data, dtype=np.object)

    def read_file(self, file_name):
        with open(os.path.join("src/test/resources/", file_name), 'rb') as f:
            return np.load(f)
