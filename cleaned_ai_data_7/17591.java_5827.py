import io

class SerializableFloatTVList:
    def __init__(self):
        pass

    @staticmethod
    def calculate_capacity(memory_limit_in_mb: float) -> int:
        memory_limit_in_b = memory_limit_in_mb * 1024 * 1024 / 2
        return (int)((memory_limit_in_b // ((8 + 4) * TSFileConfig.ARRAY_CAPACITY_THRESHOLD)))

    def __init__(self, serialization_recorder):
        super().__init__()
        self.serialization_recorder = serialization_recorder

    def serialize(self, output_stream: io.BytesIO) -> None:
        size = len(self)
        self.serialization_recorder.set_serialized_element_size(size)
        serialized_byte_length = 0
        for i in range(size):
            serialized_byte_length += ReadWriteIOUtils.write(get_time_by_index(i), output_stream)
            serialized_byte_length += ReadWriteIOUtils.write(get_float_by_index(i), output_stream)

    def deserialize(self, byte_buffer: memoryview) -> None:
        serialized_element_size = self.serialization_recorder.get_serialized_element_size()
        for i in range(serialized_element_size):
            put_float(ReadWriteIOUtils.read_long(byte_buffer), ReadWriteIOUtils.read_float(byte_buffer))

    def release(self) -> None:
        self.time_ret = None
        self.float_ret = None

class TSFileConfig:
    ARRAY_CAPACITY_THRESHOLD: int = 0

class ReadWriteIOUtils:
    LONG_LEN: int = 8
    FLOAT_LEN: int = 4

def get_time_by_index(i):
    # implement this method to return the time value at index i
    pass

def get_float_by_index(i):
    # implement this method to return the float value at index i
    pass

def put_float(time, float_value):
    # implement this method to store a float value and its corresponding time
    pass
