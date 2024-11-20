Here is the translation of the Java code into Python:

```Python
import io
from typing import List, Map, Any

class VectorMeasurementSchema:
    def __init__(self):
        pass

    def __init__(self, vector_measurement_id: str, sub_measurements: list[str], types: list[bytes], encodings: list[bytes]):
        self.vector_measurement_id = vector_measurement_id
        self.sub_measurements_to_index_map = {sub_measurement: i for i, sub_measurement in enumerate(sub_measurements)}
        self.types = bytes(types)
        self.encodings = bytes(encodings)

    def get_measurement_id(self) -> str:
        return self.vector_measurement_id

    def get_compressor(self) -> int:
        return CompressionType.deserialize(int.from_bytes(self.compressor, 'big'))

    def get_encoding_type(self) -> TSEncoding:
        raise NotImplementedError("unsupported method for VectorMeasurementSchema")

    # ... (rest of the methods)

def partial_deserialize_from(buffer: io.BytesIO) -> VectorMeasurementSchema:
    vector_measurement_schema = VectorMeasurementSchema()
    vector_measurement_schema.vector_measurement_id = buffer.read_string().decode('utf-8')
    measurement_size = int.from_bytes(buffer.read(4), 'big')
    sub_measurements_to_index_map = {}
    for _ in range(measurement_size):
        key = buffer.read_string().decode('utf-8')
        value = int.from_bytes(buffer.read(4), 'big')
        sub_measurements_to_index_map[key] = value
    vector_measurement_schema.sub_measurements_to_index_map = sub_measurements_to_index_map
    types = []
    for _ in range(measurement_size):
        types.append(int.from_bytes(buffer.read(1), 'big'))
    vector_measurement_schema.types = bytes(types)
    encodings = []
    for _ in range(measurement_size):
        encodings.append(int.from_bytes(buffer.read(1), 'big'))
    vector_measurement_schema.encodings = bytes(encodings)
    compressor = int.from_bytes(buffer.read(1), 'big')
    return vector_measurement_schema

def deserialize_from(buffer: io.BytesIO) -> VectorMeasurementSchema:
    # ... (same as partial_deserialize_from)

# rest of the methods
```

Please note that this is a direct translation from Java to Python, and it may not be perfect. The code might need some adjustments based on your specific use case.