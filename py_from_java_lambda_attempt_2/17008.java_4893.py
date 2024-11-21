Here is the translation of the Java code into Python:

```Python
class WritableMemChunk:
    def __init__(self, schema: 'IMeasurementSchema', list: 'TVList'):
        self.schema = schema
        self.list = list

    def write(self, insert_time: int, object_value):
        if isinstance(object_value, bool):
            self.put_boolean(insert_time, object_value)
        elif isinstance(object_value, int):
            self.put_int(insert_time, object_value)
        elif isinstance(object_value, float):
            self.put_float(insert_time, object_value)
        elif isinstance(object_value, (int, long)):
            self.put_long(insert_time, object_value)
        elif isinstance(object_value, str):
            self.put_binary(insert_time, Binary(object_value))
        else:
            raise UnSupportedDataTypeException("Unsupported data type: " + str(self.schema.get_type()))

    def write_times_values_bitmaps_data_type_start_end(self, times: list[int], value_list: list[object], bit_map: 'BitMap', data_type: int, start: int, end):
        if data_type == 0:
            bool_values = [bool(value) for value in value_list]
            self.put_booleans(times[start:end+1], bool_values, BitMap(bit_map), start, end)
        elif data_type == 1:
            int_values = [int(value) for value in value_list]
            self.put_ints(times[start:end+1], int_values, BitMap(bit_map), start, end)
        elif data_type == 2:
            long_values = [(long)(value) for value in value_list]
            self.put_longs(times[start:end+1], long_values, BitMap(bit_map), start, end)
        elif data_type == 3:
            float_values = [float(value) for value in value_list]
            self.put_floats(times[start:end+1], float_values, BitMap(bit_map), start, end)
        elif data_type == 4:
            double_values = [(double)(value) for value in value_list]
            self.put_doubles(times[start:end+1], double_values, BitMap(bit_map), start, end)
        elif data_type == 5:
            binary_values = [Binary(value) for value in value_list]
            self.put_binaries(times[start:end+1], binary_values, BitMap(bit_map), start, end)

    def put_long(self, t: int, v: long):
        self.list.put_long(t, v)

    def put_int(self, t: int, v: int):
        self.list.put_int(t, v)

    def put_float(self, t: int, v: float):
        self.list.put_float(t, v)

    def put_double(self, t: int, v: double):
        self.list.put_double(t, v)

    def put_binary(self, t: int, v: Binary):
        self.list.put_binary(t, v)

    def put_boolean(self, t: int, v: bool):
        self.list.put_boolean(t, v)

    def get_sorted_tv_list_for_query(self) -> 'TVList':
        if not self.list.is_sorted():
            self.list = self.list.clone()
        return self.list

    def get_sorted_tv_list_for_flush(self) -> 'TVList':
        return self.get_sorted_tv_list_for_query()

    def put_vectors(self, t: list[int], v: list[object], bit_maps: list['BitMap'], start: int, end):
        if len(v) > 0:
            for i in range(len(v)):
                if isinstance(v[i], bool):
                    self.list.put_boolean(t[start:end+1][i], v[i])
                elif isinstance(v[i], (int, long)):
                    self.list.put_long(t[start:end+1][i], v[i])
                else:
                    raise UnSupportedDataTypeException("Unsupported data type: " + str(self.schema.get_type()))
        return self.list

    def get_tv_list(self) -> 'TVList':
        return self.list

    def count(self):
        return len(self.list)

    def get_schema(self) -> 'IMeasurementSchema':
        return self.schema

    def min_time(self):
        if not hasattr(self, '_min_time'):
            self._min_time = self.list.get_min_time()
        return self._min_time

    def first_point(self):
        if len(self.list) == 0:
            return long.max_value
        else:
            return self.list.getTimeValuePair(0).getTimestamp()

    def last_point(self):
        if len(self.list) == 0:
            return long.min_value
        else:
            return self.list.getTimeValuePair(len(self.list)-1).getTimestamp()

    def delete(self, lower_bound: int, upper_bound: int):
        return self.list.delete(lower_bound, upper_bound)

class TVList:
    pass

class BitMap:
    pass

class Binary:
    pass

class IMeasurementSchema:
    pass
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.