Here is the translation of the Java code to Python:
```python
import io

class SerializableBooleanTVList:
    def __init__(self):
        pass

    @staticmethod
    def calculate_capacity(memory_limit_in_mb: float) -> int:
        memory_limit_in_b = memory_limit_in_mb * 1024 ** 2 / 2
        return (int)(memory_limit_in_b /
                     ((8 + 1) *
                      SerializableBooleanTVList.TSFileConfig.ARRAY_CAPACITY_THRESHOLD))

    def __init__(self, serialization_recorder):
        super().__init__()
        self.serialization_recorder = serialization_recorder

    def serialize(self, output_stream: io.BytesIO) -> None:
        size = len(self)
        self.serialization_recorder.set_serialized_element_size(size)
        serialized_byte_length = 0
        for i in range(size):
            serialized_byte_length += self.write_time(output_stream)
            serialized_byte_length += self.write_bool(output_stream, next(iter(self)))
        self.serialization_recorder.set_serialized_byte_length(serialized_byte_length)

    def deserialize(self, byte_buffer: memoryview) -> None:
        serialized_element_size = self.serialization_recorder.get_serialized_element_size()
        for i in range(serialized_element_size):
            time_val, bool_val = ReadWriteIOUtils.read_long(byte_buffer), ReadWriteIOUtils.read_bool(byte_buffer)
            self.put_boolean(time_val, bool_val)

    def release(self) -> None:
        self.time_ret = None
        self.boolean_ret = None

class TSFileConfig:
    ARRAY_CAPACITY_THRESHOLD: int = 0

class ReadWriteIOUtils:
    LONG_LEN: int = 8
    BOOLEAN_LEN: int = 1

def write_time(output_stream, time_val):
    # implement this method to write the time value to the output stream
    pass

def write_bool(output_stream, bool_val):
    # implement this method to write the boolean value to the output stream
    pass

def put_boolean(self, time_val, bool_val):
    # implement this method to store the time and boolean values in the object
    pass
```
Note that I had to make some assumptions about the missing implementation details (e.g., `write_time`, `write_bool`, and `put_boolean` methods). You will need to fill those in according to your specific requirements.