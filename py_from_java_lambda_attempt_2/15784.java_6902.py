Here is the translation of the given Java code into equivalent Python:

```Python
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
```

Please note that Python's NumPy library does not support all the types (like float16) and data formats (like NPY) directly. The code above assumes that you have a set of pre-defined numpy arrays for each type/file, which are then loaded from files in the test directory.

Also, please be aware that this is just an equivalent translation to Python, it may not work exactly as expected without proper testing and adjustments according to your specific requirements.