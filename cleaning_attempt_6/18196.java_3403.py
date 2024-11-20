class IntegerStatistics:
    def __init__(self):
        self.min_value = None
        self.max_value = None
        self.first_value = None
        self.last_value = None
        self.sum_value = 0

    @property
    def type(self):
        return "INT32"

    @property
    def stats_size(self):
        return 24

    def initialize_stats(self, min_val, max_val, first_val, last_val, sum_val):
        self.min_value = min_val
        self.max_value = max_val
        self.first_value = first_val
        self.last_value = last_val
        self.sum_value = sum_val

    def update_stats(self, min_val, max_val, last_val, sum_val):
        if min_val < self.min_value:
            self.min_value = min_val
        if max_val > self.max_value:
            self.max_value = max_val
        self.sum_value += sum_val
        self.last_value = last_val

    def update_stats(self, min_val, max_val, first_val, last_val, sum_val):
        if min_val < self.min_value:
            self.min_value = min_val
        if max_val > self.max_value:
            self.max_value = max_val
        self.sum_value += sum_val
        if 0 <= self.first_value and self.first_value <= first_val:
            self.first_value = first_val
        if last_val >= self.last_value:
            self.last_value = last_val

    def set_min_max_from_bytes(self, min_bytes, max_bytes):
        self.min_value = int.from_bytes(min_bytes, 'big')
        self.max_value = int.from_bytes(max_bytes, 'big')

    @property
    def is_empty(self):
        return False

    def update_stats(self, value):
        if not hasattr(self, "is_empty"):
            self.initialize_stats(value, value, value, value, value)
            setattr(self, "is_empty", True)
        else:
            self.update_stats(value)

    def update_stats(self, values, batch_size):
        for i in range(batch_size):
            self.update_stats(values[i])

    @property
    def ram_size(self):
        return 64

    @property
    def min_value(self):
        return self.min_value

    @min_value.setter
    def min_value(self, value):
        self.min_value = value

    @property
    def max_value(self):
        return self.max_value

    @max_value.setter
    def max_value(self, value):
        self.max_value = value

    @property
    def first_value(self):
        return self.first_value

    @first_value.setter
    def first_value(self, value):
        self.first_value = value

    @property
    def last_value(self):
        return self.last_value

    @last_value.setter
    def last_value(self, value):
        self.last_value = value

    def get_sum_double_value(self):
        raise StatisticsClassException("Integer statistics does not support: double sum")

    def get_sum_long_value(self):
        return self.sum_value

    def merge_statistics_value(self, stats):
        if hasattr(self, "is_empty"):
            self.initialize_stats(
                getattr(stats, "min_value"),
                getattr(stats, "max_value"),
                getattr(stats, "first_value"),
                getattr(stats, "last_value"),
                getattr(stats, "sum_value")
            )
            setattr(self, "is_empty", False)
        else:
            self.update_stats(
                getattr(stats, "min_value"),
                getattr(stats, "max_value"),
                getattr(stats, "first_value"),
                getattr(stats, "last_value"),
                getattr(stats, "sum_value"),
                stats.get_start_time(),
                stats.get_end_time()
            )

    def get_min_value_buffer(self):
        return int.to_bytes(self.min_value, 4, 'big')

    def get_max_value_buffer(self):
        return int.to_bytes(self.max_value, 4, 'big')

    def get_first_value_buffer(self):
        return int.to_bytes(self.first_value, 4, 'big')

    def get_last_value_buffer(self):
        return int.to_bytes(self.last_value, 4, 'big')

    def get_sum_value_buffer(self):
        return self.sum_value.to_bytes(8, 'big')

    @property
    def min_value_bytes(self):
        return int.to_bytes(self.min_value, 4, 'big')

    @property
    def max_value_bytes(self):
        return int.to_bytes(self.max_value, 4, 'big')

    @property
    def first_value_bytes(self):
        return int.to_bytes(self.first_value, 4, 'big')

    @property
    def last_value_bytes(self):
        return int.to_bytes(self.last_value, 4, 'big')

    @property
    def sum_value_bytes(self):
        return self.sum_value.to_bytes(8, 'big')

    def serialize_stats(self, outputStream):
        byte_len = 0
        byte_len += int.to_bytes(self.min_value, 4, 'big').write_to(outputStream)
        byte_len += int.to_bytes(self.max_value, 4, 'big').write_to(outputStream)
        byte_len += int.to_bytes(self.first_value, 4, 'big').write_to(outputStream)
        byte_len += int.to_bytes(self.last_value, 4, 'big').write_to(outputStream)
        byte_len += self.sum_value.to_bytes(8, 'big').write_to(outputStream)
        return byte_len

    def deserialize(self, inputStream):
        self.min_value = int.from_bytes(inputStream.read(4), 'big')
        self.max_value = int.from_bytes(inputStream.read(4), 'big')
        self.first_value = int.from_bytes(inputStream.read(4), 'big')
        self.last_value = int.from_bytes(inputStream.read(4), 'big')
        self.sum_value = int.from_bytes(inputStream.read(8), 'big')

    def deserialize(self, byteBuffer):
        self.min_value = int.from_bytes(byteBuffer[:4], 'big')
        self.max_value = int.from_bytes(byteBuffer[4:8], 'big')
        self.first_value = int.from_bytes(byteBuffer[8:12], 'big')
        self.last_value = int.from_bytes(byteBuffer[12:16], 'big')
        self.sum_value = int.from_bytes(byteBuffer[16:], 'big')

    def __str__(self):
        return f"IntegerStatistics[minValue={self.min_value}, maxValue={self.max_value}, firstValue={self.first_value}, lastValue={self.last_value}, sumValue={self.sum_value}]"
