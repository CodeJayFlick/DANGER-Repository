class BooleanStatistics:
    def __init__(self):
        self.first_value = None
        self.last_value = None
        self.sum_value = 0

    @property
    def type(self):
        return "BOOLEAN"

    @property
    def stats_size(self):
        return 10

    def initialize_stats(self, first_value: bool, last_value: bool, sum_value: int) -> None:
        self.first_value = first_value
        self.last_value = last_value
        self.sum_value = sum_value

    def update_stats(self, last_value: bool, sum_value: int) -> None:
        self.last_value = last_value
        self.sum_value += sum_value

    def update_stats(
            self,
            first_value: bool,
            last_value: bool,
            start_time: int,
            end_time: int,
            sum_value: int
    ) -> None:
        if start_time <= self.get_start_time():
            self.first_value = first_value
        if end_time >= self.get_end_time():
            self.last_value = last_value
        self.sum_value += sum_value

    def update_stats(self, value: bool) -> None:
        if not hasattr(self, 'first_value'):
            self.initialize_stats(value, value, 1 if value else 0)
        else:
            self.update_stats(value, 1 if value else 0)

    def update_stats(self, values: list[bool], batch_size: int) -> None:
        for i in range(batch_size):
            self.update_stats(values[i])

    @property
    def ram_size(self):
        return 56

    def set_min_max_from_bytes(self, min_bytes: bytes, max_bytes: bytes) -> None:
        pass

    def get_min_value(self) -> bool:
        raise StatisticsClassException("Boolean statistics does not support: min")

    def get_max_value(self) -> bool:
        raise StatisticsClassException("Boolean statistics does not support: max")

    @property
    def first_value_(self):
        return self.first_value

    @property
    def last_value_(self):
        return self.last_value

    def get_sum_double_value(self) -> float:
        raise StatisticsClassException("Boolean statistics does not support: double sum")

    @property
    def sum_long_value(self):
        return self.sum_value

    def get_min_value_buffer(self) -> bytes:
        raise StatisticsClassException("Boolean statistics do not support: min")

    def get_max_value_buffer(self) -> bytes:
        raise StatisticsClassException("Boolean statistics do not support: max")

    @property
    def first_value_buffer_(self):
        return ReadWriteIOUtils.bool_to_bytes(self.first_value)

    @property
    def last_value_buffer_(self):
        return ReadWriteIOUtils.bool_to_bytes(self.last_value)

    @property
    def sum_value_buffer_(self):
        return ReadWriteIOUtils.int64_to_bytes(self.sum_value)

    def merge_statistics_value(self, stats: 'BooleanStatistics') -> None:
        if not hasattr(self, 'first_value'):
            self.initialize_stats(stats.first_value_, stats.last_value_, stats.sum_long_value)
        else:
            self.update_stats(
                stats.first_value_,
                stats.last_value_,
                stats.get_start_time(),
                stats.get_end_time(),
                stats.sum_long_value
            )

    def get_min_value_bytes(self) -> bytes:
        raise StatisticsClassException("Boolean statistics does not support: min")

    def get_max_value_bytes(self) -> bytes:
        raise StatisticsClassException("Boolean statistics do not support: max")

    @property
    def first_value_bytes_(self):
        return ReadWriteIOUtils.bool_to_bytes(self.first_value)

    @property
    def last_value_bytes_(self):
        return ReadWriteIOUtils.bool_to_bytes(self.last_value)

    @property
    def sum_value_bytes_(self):
        return ReadWriteIOUtils.int64_to_bytes(self.sum_value)

    def serialize_stats(self, output_stream: bytes) -> int:
        byte_len = 0
        byte_len += len(ReadWriteIOUtils.bool_to_bytes(self.first_value))
        byte_len += len(ReadWriteIOUtils.bool_to_bytes(self.last_value))
        byte_len += len(ReadWriteIOUtils.int64_to_bytes(self.sum_value))
        return byte_len

    def deserialize(self, input_stream: bytes) -> None:
        self.first_value = ReadWriteIOUtils.read_bool(input_stream)
        self.last_value = ReadWriteIOUtils.read_bool(input_stream)
        self.sum_value = ReadWriteIOUtils.read_int64(input_stream)

    def deserialize(self, byte_buffer: bytearray) -> None:
        self.first_value = ReadWriteIOUtils.read_bool(byte_buffer)
        self.last_value = ReadWriteIOUtils.read_bool(byte_buffer)
        self.sum_value = ReadWriteIOUtils.read_int64(byte_buffer)

    @property
    def __str__(self):
        return f"{super().__str__}[first_value={self.first_value}, last_value={self.last_value}, sum_value={self.sum_value}]"
