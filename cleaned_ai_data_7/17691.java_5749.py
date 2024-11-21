class QueryDataSetUtils:
    def __init__(self):
        pass

    @staticmethod
    def convert_query_dataset_by_fetch_size(query_data_set: 'QueryDataSet', fetch_size: int, watermark_encoder=None) -> 'TSQueryDataSet':
        data_types = query_data_set.get_data_types()
        column_num = len(data_types)
        ts_query_data_set = TSQueryDataSet()

        # one time column and each value column has a actual value buffer and a bitmap value to
        # indicate whether it is a null
        column_num_with_time = (column_num * 2) + 1

        data_output_streams = [ByteArrayOutputStream() for _ in range(column_num_with_time)]
        byte_array_output_streams = [DataOutputStream(data_output_stream) for data_output_stream in data_output_streams]

        row_count = 0
        value_occupation = [0] * column_num
        bitmap = [0] * column_num

        while True:
            if query_data_set.has_next():
                row_record = query_data_set.next()
                # filter rows whose columns are null according to the rule
                if (query_data_set.is_without_all_null() and row_record.is_all_null()) or \
                   (query_data_set.is_without_any_null() and row_record.has_null_field()):
                    query_data_set.decrease_already_returned_row_num()
                    continue

                if watermark_encoder is not None:
                    row_record = watermark_encoder.encode_record(row_record)

                data_output_streams[0].write_long(row_record.get_timestamp())
                fields = row_record.get_fields()

                for k, field in enumerate(fields):
                    if field is None or field.get_data_type() is None:
                        bitmap[k] |= 1
                    else:
                        bitmap[k] &= ~1
                        ts_data_type = field.get_data_type()
                        switch (ts_data_type):
                            case 'INT32':
                                data_output_streams[2 * k + 1].write_int(field.get_int_v())
                                value_occupation[k] += 4
                                break
                            case 'INT64':
                                data_output_streams[2 * k + 1].write_long(field.get_long_v())
                                value_occupation[k] += 8
                                break
                            case 'FLOAT':
                                data_output_streams[2 * k + 1].write_float(field.get_float_v())
                                value_occupation[k] += 4
                                break
                            case 'DOUBLE':
                                data_output_stream = data_output_streams[2 * k + 1]
                                data_output_stream.write_double(field.get_double_v())
                                value_occupation[k] += 8
                                break
                            case 'BOOLEAN':
                                data_output_stream = data_output_streams[2 * k + 1]
                                data_output_stream.write_boolean(field.get_bool_v())
                                value_occupation[k] += 1
                                break
                            case 'TEXT':
                                data_output_stream = data_output_streams[2 * k + 1]
                                length = field.get_binary_v().get_length()
                                data_output_stream.write_int(length)
                                data_output_stream.write(field.get_binary_v().get_values())
                                value_occupation[k] += (4 + length)
                                break
                            default:
                                raise UnSupportedDataTypeException(f"Data type {ts_data_type} is not supported.")

                row_count += 1

                if row_count % 8 == 0:
                    for j in range(len(bitmap)):
                        data_output_stream = byte_array_output_streams[2 * (j + 1)]
                        data_output_stream.write_byte(bitmap[j])
                        bitmap[j] &= ~7
            else:
                break

        # feed the remaining bitmap
        if row_count % 8 != 0:
            for j in range(len(bitmap)):
                data_output_stream = byte_array_output_streams[2 * (j + 1)]
                data_output_stream.write_byte((bitmap[j] << (8 - (row_count % 8))))

        # calculate the time buffer size
        time_occupation = row_count * 8

        if time_occupation > 0:
            time_buffer = bytearray(time_occupation)
            for i in range(len(data_output_streams[0].to_array())):
                time_buffer[i] = data_output_streams[0].get_byte()
            ts_query_data_set.set_time(bytearray_to_buffer(time_buffer))

        # calculate the bitmap buffer size
        if row_count % 8 != 0:
            bitmap_occupation = (row_count // 8) + 1

        else:
            bitmap_occupation = row_count // 8

        value_list = []
        for i in range(1, len(byte_array_output_streams), 2):
            buffer = bytearray(value_occupation[(i - 1) // 2])
            for j in range(len(data_output_stream)):
                buffer[j] = data_output_stream.get_byte()
            ts_query_data_set.set_value_list([bytearray_to_buffer(buffer)])

        return ts_query_data_set

    @staticmethod
    def read_times_from_buffer(buffer: bytearray, size: int) -> list:
        times = [0] * size
        for i in range(size):
            times[i] = buffer.read_long()
        return times

    @staticmethod
    def read_bitmaps_from_buffer(buffer: bytearray, columns: int, size: int) -> list:
        if not buffer.has_remaining():
            return None

        bit_maps = [None] * columns
        for i in range(columns):
            has_bitmap = BytesUtils.byte_to_bool(buffer.read_byte())
            if has_bitmap:
                bytes = [0] * (size // Byte.SIZE + 1)
                for j in range(len(bytes)):
                    bytes[j] = buffer.get_byte()
                bit_maps[i] = BitMap(size, bytes)

        return bit_maps

    @staticmethod
    def read_values_from_buffer(buffer: bytearray, types: list, columns: int, size: int) -> list:
        values = [None] * columns
        for i in range(columns):
            switch (types[i]):
                case 'BOOLEAN':
                    bool_values = [0] * size
                    for j in range(size):
                        bool_values[j] = BytesUtils.byte_to_bool(buffer.read_byte())
                    values[i] = bool_values
                    break
                case 'INT32':
                    int_values = [0] * size
                    for j in range(size):
                        int_values[j] = buffer.read_int()
                    values[i] = int_values
                    break
                case 'INT64':
                    long_values = [0] * size
                    for j in range(size):
                        long_values[j] = buffer.read_long()
                    values[i] = long_values
                    break
                case 'FLOAT':
                    float_values = [0.0] * size
                    for j in range(size):
                        float_values[j] = buffer.read_float()
                    values[i] = float_values
                    break
                case 'DOUBLE':
                    double_values = [0.0] * size
                    for j in range(size):
                        double_values[j] = buffer.read_double()
                    values[i] = double_values
                    break
                case 'TEXT':
                    binary_values = [None] * size
                    for j in range(size):
                        length = buffer.read_int()
                        byte_array = bytearray(length)
                        for k in range(len(byte_array)):
                            byte_array[k] = buffer.get_byte()
                        binary_values[j] = Binary(byte_array)
                    values[i] = binary_values
                    break

        return values


class TSQueryDataSet:
    def __init__(self):
        pass

    @staticmethod
    def set_time(time: bytearray) -> None:
        pass

    @staticmethod
    def set_bitmap_list(bitmap_list: list) -> None:
        pass

    @staticmethod
    def set_value_list(value_list: list) -> None:
        pass


class BitMap:
    def __init__(self, size: int, bytes: bytearray):
        self.size = size
        self.bytes = bytes

    @staticmethod
    def from_buffer(buffer: bytearray, size: int) -> 'BitMap':
        if not buffer.has_remaining():
            return None

        bit_map = BitMap(size, [0] * ((size // Byte.SIZE + 1)))
        for j in range(len(bit_map.bytes)):
            bit_map.bytes[j] = buffer.get_byte()
        return bit_map


class Binary:
    def __init__(self, byte_array: bytearray):
        self.byte_array = byte_array

    @staticmethod
    def from_buffer(buffer: bytearray) -> 'Binary':
        length = buffer.read_int()
        byte_array = [0] * (length)
        for j in range(len(byte_array)):
            byte_array[j] = buffer.get_byte()
        return Binary(byte_array)


class DataOutputStream:
    def __init__(self, stream):
        self.stream = stream

    @staticmethod
    def from_buffer(buffer: bytearray) -> 'DataOutputStream':
        pass


class ByteArrayOutputStream:
    def __init__(self):
        pass

    @staticmethod
    def from_buffer(buffer: bytearray) -> 'ByteArrayOutputStream':
        return buffer


def bytearray_to_buffer(byte_array: bytearray) -> bytearray:
    return byte_array


# usage example:

query_data_set = QueryDataSet()
fetch_size = 1000
watermark_encoder = None

ts_query_data_set = QueryDataSetUtils.convert_query_dataset_by_fetch_size(query_data_set, fetch_size, watermark_encoder)

times = QueryDataSetUtils.read_times_from_buffer(ts_query_data_set.get_time(), len(times))
bit_maps = QueryDataSetUtils.read_bitmaps_from_buffer(ts_query_data_set.get_bitmap_list()[0], 1, len(bit_maps[0]))
values = QueryDataSetUtils.read_values_from_buffer(ts_query_data_set.get_value_list()[0], [TSDataType.BOOLEAN] * len(values), 1, len(values))
