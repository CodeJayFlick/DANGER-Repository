Here is the translation of the given Java code into equivalent Python:

```Python
class SerializableBinaryTVList:
    MIN_OBJECT_HEADER_SIZE = 8
    MIN_ARRAY_HEADER_SIZE = MIN_OBJECT_HEADER_SIZE + 4

    @staticmethod
    def calculate_capacity(memory_limit_in_mb, byte_array_length):
        memory_limit_in_b = memory_limit_in_mb * 1024 ** 2 / 2
        return int((memory_limit_in_b /
                    (TSFileConfig.ARRAY_CAPACITY_THRESHOLD *
                     SerializableBinaryTVList.calculate_single_binary_tv_pair_memory(byte_array_length)))

    @staticmethod
    def calculate_single_binary_tv_pair_memory(byte_array_length):
        return ReadWriteIOUtils.LONG_LEN + \
               SerializableBinaryTVList.MIN_OBJECT_HEADER_SIZE + \
               SerializableBinaryTVList.MIN_ARRAY_HEADER_SIZE + byte_array_length

    def __init__(self, serialization_recorder):
        super().__init__(TSDataType.TEXT, serialization_recorder)

    def serialize(self, output_stream):
        size = len(self)
        self.serialization_recorder.set_serialized_element_size(size)
        serialized_byte_length = 0
        for i in range(size):
            serialized_byte_length += ReadWriteIOUtils.write(get_time_by_index(i), output_stream)
            serialized_byte_length += ReadWriteIOUtils.write(get_binary_by_index(i), output_stream)
        self.serialization_recorder.set_serialized_byte_length(serialized_byte_length)

    def deserialize(self, byte_buffer):
        serialized_element_size = self.serialization_recorder.get_serialized_element_size()
        for i in range(serialized_element_size):
            put_binary(ReadWriteIOUtils.read_long(byte_buffer),
                       ReadWriteIOUtils.read_binary(byte_buffer))

    def release(self):
        self.time_ret = None
        self.binary_ret = None

class TSFileConfig:
    ARRAY_CAPACITY_THRESHOLD = 0

class ReadWriteIOUtils:
    LONG_LEN = 8
```

Note: The above Python code is equivalent to the given Java code. However, it may not be a direct translation as some parts of the original code are missing (like `TSDataType`, `SerializationRecorder` and their methods).