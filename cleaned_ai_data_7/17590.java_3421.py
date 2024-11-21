import io

class SerializableDoubleTVList:
    def __init__(self):
        pass

    @staticmethod
    def calculate_capacity(memory_limit_in_mb: float) -> int:
        memory_limit_in_b = memory_limit_in_mb * 1024 ** 2 / 2
        return (int((memory_limit_in_b /
                      ((8 + 8) * TSFileConfig.ARRAY_CAPACITY_THRESHOLD))))

    def __init__(self, serialization_recorder):
        super().__init__()
        self.serialization_recorder = serialization_recorder

    def serialize(self, output_stream: io.BytesIO) -> None:
        size = len(self)
        self.serialization_recorder.set_serialized_element_size(size)
        serialized_byte_length = 0
        for i in range(len(self)):
            serialized_byte_length += self.write_time(output_stream)
            serialized_byte_length += self.write_double(output_stream)
        self.serialization_recorder.set_serialized_byte_length(serialized_byte_length)

    def deserialize(self, byte_buffer: memoryview) -> None:
        serialized_element_size = self.serialization_recorder.get_serialized_element_size()
        for i in range(serialized_element_size):
            time_value, double_value = ReadWriteIOUtils.read_long_double(byte_buffer)
            self.put_double(time_value, double_value)

    def release(self) -> None:
        self.time_ret = None
        self.double_ret = None

class TSFileConfig:
    ARRAY_CAPACITY_THRESHOLD: int = 0

class ReadWriteIOUtils:
    LONG_LEN: int = 8
    DOUBLE_LEN: int = 8

def put_double(self, time_value: float, double_value: float) -> None:
    pass

def write_time(self, output_stream: io.BytesIO) -> int:
    pass

def write_double(self, output_stream: io.BytesIO) -> int:
    pass
