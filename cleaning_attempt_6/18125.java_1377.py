class DeltaBinaryDecoder:
    def __init__(self):
        self.count = 0
        self.delta_buf = None
        self.read_int_total_count = 0
        self.next_read_index = 0
        self.pack_width = 0
        self.pack_num = 0
        self.encoding_length = 0

    def read_header(self, buffer):
        pass  # abstract method to be implemented by subclasses

    def allocate_data_array(self):
        pass  # abstract method to be implemented by subclasses

    def read_value(self, i):
        pass  # abstract method to be implemented by subclasses

    @staticmethod
    def ceil(v):
        return -(-v // 8)

    def has_next(self, buffer):
        if self.next_read_index < self.read_int_total_count:
            return True
        return buffer.remaining() > 0


class IntDeltaDecoder(DeltaBinaryDecoder):
    def __init__(self):
        super().__init__()

    def read_t(self, buffer):
        if self.next_read_index == self.read_int_total_count:
            return self.load_int_batch(buffer)
        return self.data[self.next_read_index]

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    def load_int_batch(self, buffer):
        self.pack_num = int.from_bytes(buffer.read(4), 'big')
        self.pack_width = int.from_bytes(buffer.read(4), 'big')
        self.count += 1
        self.read_header(buffer)
        self.encoding_length = -(-self.pack_num * self.pack_width // 8)
        self.delta_buf = buffer.read(self.encoding_length)
        self.allocate_data_array()
        self.previous = self.first_value
        self.read_int_total_count = self.pack_num
        self.next_read_index = 0
        self.read_pack()
        return self.first_value

    def read_pack(self):
        for i in range(self.pack_num):
            self.read_value(i)
            self.previous = self.data[i]

    @property
    def first_value(self):
        return self._first_value

    @first_value.setter
    def first_value(self, value):
        self._first_value = value

    @property
    def previous(self):
        return self._previous

    @previous.setter
    def previous(self, value):
        self._previous = value

    @property
    def min_delta_base(self):
        return self._min_delta_base

    @min_delta_base.setter
    def min_delta_base(self, value):
        self._min_delta_base = value

    def read_header(self, buffer):
        self.min_delta_base = int.from_bytes(buffer.read(4), 'big')
        self.first_value = int.from_bytes(buffer.read(4), 'big')

    def allocate_data_array(self):
        self.data = [0] * self.pack_num

    def read_value(self, i):
        v = int.from_bytes(self.delta_buf[i*self.pack_width:(i+1)*self.pack_width], 'big')
        self.data[i] = self.previous + self.min_delta_base + v


class LongDeltaDecoder(DeltaBinaryDecoder):
    def __init__(self):
        super().__init__()

    def read_t(self, buffer):
        if self.next_read_index == self.read_int_total_count:
            return self.load_int_batch(buffer)
        return self.data[self.next_read_index]

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    def load_int_batch(self, buffer):
        self.pack_num = int.from_bytes(buffer.read(4), 'big')
        self.pack_width = int.from_bytes(buffer.read(4), 'big')
        self.count += 1
        self.read_header(buffer)
        self.encoding_length = -(-self.pack_num * self.pack_width // 8)
        self.delta_buf = buffer.read(self.encoding_length)
        self.allocate_data_array()
        self.previous = self.first_value
        self.read_int_total_count = self.pack_num
        self.next_read_index = 0
        self.read_pack()
        return self.first_value

    def read_pack(self):
        for i in range(self.pack_num):
            self.read_value(i)
            self.previous = self.data[i]

    @property
    def first_value(self):
        return self._first_value

    @first_value.setter
    def first_value(self, value):
        self._first_value = value

    @property
    def previous(self):
        return self._previous

    @previous.setter
    def previous(self, value):
        self._previous = value

    @property
    def min_delta_base(self):
        return self._min_delta_base

    @min_delta_base.setter
    def min_delta_base(self, value):
        self._min_delta_base = value

    def read_header(self, buffer):
        self.min_delta_base = int.from_bytes(buffer.read(8), 'big')
        self.first_value = int.from_bytes(buffer.read(8), 'big')

    def allocate_data_array(self):
        self.data = [0] * self.pack_num

    def read_value(self, i):
        v = int.from_bytes(self.delta_buf[i*self.pack_width:(i+1)*self.pack_width], 'big')
        self.data[i] = self.previous + self.min_delta_base + v


class Decoder:
    pass  # abstract class
