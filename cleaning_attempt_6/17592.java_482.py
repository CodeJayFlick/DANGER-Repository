import io

class SerializableIntTVList:
    def __init__(self):
        pass

    @staticmethod
    def calculate_capacity(memory_limit_in_mb: float) -> int:
        memory_limit_in_b = memory_limit_in_mb * 1024 ** 2 / 2
        return (int)(memory_limit_in_b /
                     ((8 + 4) * SerializableIntTVList.TSFileConfig.ARRAY_CAPACITY_THRESHOLD))

    def __init__(self, serialization_recorder):
        super().__init__()
        self.serialization_recorder = serialization_recorder

    def serialize(self, output_stream: io.BytesIO) -> None:
        size = len(self)
        self.serialization_recorder.set_serialized_element_size(size)
        serialized_byte_length = 0
        for i in range(size):
            serialized_byte_length += self.write_time(output_stream)
            serialized_byte_length += self.write_int(output_stream)
        self.serialization_recorder.set_serialized_byte_length(serialized_byte_length)

    def deserialize(self, byte_buffer: memoryview) -> None:
        serialized_element_size = self.serialization_recorder.get_serialized_element_size()
        for i in range(serialized_element_size):
            time_value = ReadWriteIOUtils.read_long(byte_buffer)
            int_value = ReadWriteIOUtils.read_int(byte_buffer)
            self.put_int(time_value, int_value)

    def release(self) -> None:
        self.time_ret = None
        self.int_ret = None

SerializableIntTVList.TSFileConfig = {
    'ARRAY_CAPACITY_THRESHOLD': 1024 ** 2,
}

class ReadWriteIOUtils:
    @staticmethod
    def read_long(byte_buffer: memoryview) -> int:
        # implement me!
        pass

    @staticmethod
    def read_int(byte_buffer: memoryview) -> int:
        # implement me!
        pass

    @staticmethod
    def write_time(output_stream: io.BytesIO, time_value: int) -> None:
        # implement me!
        pass

    @staticmethod
    def write_int(output_stream: io.BytesIO, int_value: int) -> None:
        # implement me!
        pass
