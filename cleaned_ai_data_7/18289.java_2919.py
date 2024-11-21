class ValuePageReader:
    def __init__(self, page_data=None, data_type=None, value_decoder=None):
        self.data_type = data_type
        self.value_decoder = value_decoder
        if page_data is not None:
            self.split_data_to_bitmap_and_value(page_data)

    @staticmethod
    def read_int(byte_buffer):
        return int.from_bytes(byte_buffer.read(4), 'little')

    @staticmethod
    def read_boolean(byte_buffer):
        return bool(int.from_bytes(byte_buffer.read(1), 'little'))

    @staticmethod
    def read_float(byte_buffer):
        return struct.unpack('<f', byte_buffer.read(4))[0]

    @staticmethod
    def read_double(byte_buffer):
        return struct.unpack('<d', byte_buffer.read(8))[0]

    @staticmethod
    def read_long(byte_buffer):
        return int.from_bytes(byte_buffer.read(8), 'little')

    @staticmethod
    def read_binary(byte_buffer, length):
        binary = bytearray(length)
        for i in range(length):
            binary[i] = byte_buffer.read(1)[0]
        return bytes(binary)

    def split_data_to_bitmap_and_value(self, page_data):
        self.size = ValuePageReader.read_int(page_data)
        bitmap = bytearray((self.size + 7) // 8)
        page_data.seek(4)
        for i in range(len(bitmap)):
            byte_val = int.from_bytes(page_data.read(1), 'little')
            mask = (0x80 >> (i % 8))
            if byte_val & mask:
                bitmap[i] |= mask
        self.value_buffer = page_data

    def next_batch(self, time_batch, ascending, filter):
        batch_data = BatchDataFactory.create_batch_data(self.data_type, ascending, False)
        for i in range(len(time_batch)):
            timestamp = time_batch[i]
            if not is_deleted(timestamp) and (filter is None or filter.satisfy(timestamp, self.read_boolean(self.value_buffer))):
                batch_data.put_bool(timestamp, True)
        return batch_data.flip()

    def next_value_batch(self, time_batch):
        value_batch = [None] * len(time_batch)
        for i in range(len(time_batch)):
            if not is_deleted(time_batch[i]):
                if self.data_type == TSDataType.BOOLEAN:
                    aBoolean = self.read_boolean(self.value_buffer)
                    value_batch[i] = TsPrimitiveType.TsBoolean(aBoolean)
                elif self.data_type == TSDataType.INT32:
                    anInt = ValuePageReader.read_int(self.value_buffer)
                    value_batch[i] = TsPrimitiveType.TsInt(anInt)
                elif self.data_type == TSDataType.INT64:
                    aLong = ValuePageReader.read_long(self.value_buffer)
                    value_batch[i] = TsPrimitiveType.TsLong(aLong)
                elif self.data_type == TSDataType.FLOAT:
                    aFloat = ValuePageReader.read_float(self.value_buffer)
                    value_batch[i] = TsPrimitiveType.TsFloat(aFloat)
                elif self.data_type == TSDataType.DOUBLE:
                    aDouble = ValuePageReader.read_double(self.value_buffer)
                    value_batch[i] = TsPrimitiveType.TsDouble(aDouble)
                else:  # TSDataType.TEXT
                    length = int.from_bytes(self.value_buffer.read(4), 'little')
                    binary = self.read_binary(self.value_buffer, length)
                    value_batch[i] = TsPrimitiveType.TsBinary(binary)
        return value_batch

    def get_statistics(self):
        return self.page_header.get_statistics()

    def set_delete_interval_list(self, list):
        self.delete_interval_list = list

    def get_delete_interval_list(self):
        return self.delete_interval_list

    def is_modified(self):
        return self.page_header.is_modified()

    @staticmethod
    def is_deleted(timestamp):
        while ValuePageReader.delete_interval_list is not None and ValuePageReader.delete_cursor < len(ValuePageReader.delete_interval_list):
            if ValuePageReader.delete_interval_list[ValuePageReader.delete_cursor].contains(timestamp):
                return True
            elif ValuePageReader.delete_interval_list[ValuePageReader.delete_cursor].get_max() < timestamp:
                ValuePageReader.delete_cursor += 1
            else:
                return False
        return False

    def get_data_type(self):
        return self.data_type


class BatchDataFactory:

    @staticmethod
    def create_batch_data(data_type, ascending, is_sorted):
        pass


class TsPrimitiveType:

    class TsBoolean:
        def __init__(self, value):
            self.value = value

    class TsInt:
        def __init__(self, value):
            self.value = value

    class TsLong:
        def __init__(self, value):
            self.value = value

    class TsFloat:
        def __init__(self, value):
            self.value = value

    class TsDouble:
        def __init__(self, value):
            self.value = value

    class TsBinary:
        def __init__(self, binary):
            self.binary = binary


class TimeRange:

    def __init__(self, min_value, max_value):
        self.min_value = min_value
        self.max_value = max_value

    @staticmethod
    def create_time_range(min_value, max_value):
        return TimeRange(min_value, max_value)

    def contains(self, timestamp):
        if timestamp >= self.min_value and timestamp <= self.get_max():
            return True
        else:
            return False

    def get_min(self):
        return self.min_value

    def set_min(self, min_value):
        self.min_value = min_value

    def get_max(self):
        return self.max_value

    def set_max(self, max_value):
        self.max_value = max_value


class PageHeader:

    @staticmethod
    def create_page_header():
        pass

    def is_modified(self):
        pass

    def get_statistics(self):
        pass


TSDataType = {
    'BOOLEAN': 0,
    'INT32': 1,
    'INT64': 2,
    'FLOAT': 3,
    'DOUBLE': 4,
    'TEXT': 5
}
