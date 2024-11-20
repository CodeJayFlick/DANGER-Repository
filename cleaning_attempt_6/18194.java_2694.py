class DoubleStatistics:
    def __init__(self):
        self.min_value = None
        self.max_value = None
        self.first_value = None
        self.last_value = None
        self.sum_value = 0.0

    @property
    def type(self):
        return "DOUBLE"

    @property
    def stats_size(self):
        return 40

    def initialize_stats(self, min_value, max_value, first_value, last_value, sum_value):
        self.min_value = min_value
        self.max_value = max_value
        self.first_value = first_value
        self.last_value = last_value
        self.sum_value = sum_value

    def update_stats(self, minValue=None, maxValue=None, lastValue=None, sumValue=0.0):
        if minValue is not None and minValue < self.min_value:
            self.min_value = minValue
        if maxValue is not None and maxValue > self.max_value:
            self.max_value = maxValue
        self.sum_value += sumValue
        self.last_value = lastValue

    def serialize_stats(self, outputStream):
        byte_len = 0
        byte_len += ReadWriteIOUtils.write(self.min_value, outputStream)
        byte_len += ReadWriteIOUtils.write(self.max_value, outputStream)
        byte_len += ReadWriteIOUtils.write(self.first_value, outputStream)
        byte_len += ReadWriteIOUtils.write(self.last_value, outputStream)
        byte_len += ReadWriteIOUtils.write(self.sum_value, outputStream)
        return byte_len

    def deserialize(self, inputStream):
        self.min_value = ReadWriteIOUtils.read_double(inputStream)
        self.max_value = ReadWriteIOUtils.read_double(inputStream)
        self.first_value = ReadWriteIOUtils.read_double(inputStream)
        self.last_value = ReadWriteIOUtils.read_double(inputStream)
        self.sum_value = ReadWriteIOUtils.read_double(inputStream)

    def deserialize(self, byteBuffer):
        self.min_value = ReadWriteIOUtils.read_double(byteBuffer)
        self.max_value = ReadWriteIOUtils.read_double(byteBuffer)
        self.first_value = ReadWriteIOUtils.read_double(byteBuffer)
        self.last_value = ReadWriteIOUtils.read_double(byteBuffer)
        self.sum_value = ReadWriteIOUtils.read_double(byteBuffer)

    def __str__(self):
        return f"[minValue: {self.min_value}, maxValue: {self.max_value}, firstValue: {self.first_value}, lastValue: {self.last_value}, sumValue: {self.sum_value}]"
