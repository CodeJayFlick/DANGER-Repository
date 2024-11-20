Here is the translation of the Java code into Python:

```Python
class DoubleTVList:
    def __init__(self):
        self.values = []
        self.sorted_values = None
        self.pivot_value = None

    def put_double(self, timestamp: int, value: float) -> None:
        if len(self.values) == 0 or (len(self.values[-1]) >= ARRAY_SIZE and 
            ((timestamp - self.get_time(len(self.values))) % ARRAY_SIZE != 0)):
            self.values.append([timestamp] + [value])
        else:
            last_array = self.values[-1]
            last_array.extend([(timestamp, value)])
        
        if len(self.values) > 1 and timestamp < self.get_time(-2):
            self.sorted = False

    def get_double(self, index: int) -> float:
        if index >= len(self.values[0]):
            raise ArrayIndexOutOfBoundsException(index)
        array_index = index // ARRAY_SIZE
        element_index = index % ARRAY_SIZE
        return self.values[array_index][element_index]

    def set(self, index: int, timestamp: int, value: float) -> None:
        if index >= len(self.values[0]):
            raise ArrayIndexOutOfBoundsException(index)
        array_index = index // ARRAY_SIZE
        element_index = index % ARRAY_SIZE
        self.values[array_index][element_index] = (timestamp, value)

    def clone(self) -> 'DoubleTVList':
        new_list = DoubleTVList()
        for v in self.values:
            new_list.values.append(v[:])
        return new_list

    def sort(self):
        if not hasattr(self, 'sorted_timestamps'):
            self.sorted_timestamps = [(0,) * len(self.values[0]) for _ in range(len(self.values))]
        if not hasattr(self, 'sorted_values'):
            self.sorted_values = [[(0.0,) for _ in range(len(self.values[0]))] 
                                  for _ in range(len(self.values))]

        self.sort(0, len(self.values))
        self.clear_sorted_value()
        self.clear_sorted_time()
        self.sorted = True

    def clear_value(self) -> None:
        if hasattr(self, 'values'):
            for v in self.values:
                PrimitiveArrayManager.release(v)
            self.values.clear()

    def set_from_sorted(self, src: int, dest: int):
        timestamp, value = self.get_time(src), self.get_double(src)
        self.set(dest, timestamp[0], value)

    def set_to_sorted(self, src: int, dest: int) -> None:
        self.sorted_timestamps[dest // ARRAY_SIZE][dest % ARRAY_SIZE] = self.get_time(src)[0]
        self.sorted_values[dest // ARRAY_SIZE][dest % ARRAY_SIZE] = self.get_double(src)

    def reverse_range(self, lo: int, hi: int):
        while lo < hi:
            timestamp, value = self.get_time(lo), self.get_double(lo)
            dest_timestamp, _ = self.get_time(hi), self.get_double(hi)
            self.set(lo++, dest_timestamp[0], dest_value)
            self.set(hi--, timestamp[0], value)

    def expand_values(self) -> None:
        self.values.append(get_primitive_arrays_by_type(TSDataType.DOUBLE))

    def save_as_pivot(self, pos: int):
        pivot_time = self.get_time(pos)[0]
        pivot_value = self.get_double(pos)
        self.pivot_time = pivot_time
        self.pivot_value = pivot_value

    def set_pivot_to(self, pos: int) -> None:
        timestamp, value = self.get_time(pos), self.get_double(pos)
        self.set(pos, (timestamp[0],), value)

    def get_timeValuePair(self, index: int):
        return TimeValuePair((self.get_time(index)[0], TsPrimitiveType.get_by_type(TSDataType.DOUBLE, 
            self.get_double(index))))

    def release_last_value_array(self) -> None:
        PrimitiveArrayManager.release(self.values.pop())

    def put_doubles(self, time: list[int], value: list[float], bit_map: BitMap, start: int, end: int):
        if len(time) + time_idx_offset == len(value):
            # constraint: time.length + timeIdxOffset == value.length
            idx = start
            while idx < end:
                array_index = size // ARRAY_SIZE
                element_index = size % ARRAY_SIZE
                internal_remaining = ARRAY_SIZE - element_index

                if internal_remaining >= input_remaining:
                    System.arraycopy(time, idx - time_idx_offset, timestamps.get(array_index), 
                        element_index, input_remaining)
                    System.arraycopy(value, idx, values.get(array_index), element_index, input_remaining)
                    size += input_remaining
                    break
                else:
                    # the remaining inputs cannot fit the last array, fill the last array and create a new one
                    System.arraycopy(time, idx - time_idx_offset, timestamps.get(array_index), 
                        element_index, internal_remaining)
                    System.arraycopy(value, idx, values.get(array_index), element_index, internal_remaining)
                    idx += internal_remaining
                    size += internal_remaining

    def drop_null_val_then_update_min_time_and_sorted(self):
        in_put_min_time = Long.MAX_VALUE
        input_sorted = True

        null_cnt = 0
        for v_idx in range(start, end):
            if bit_map.is_marked(v_idx):
                null_cnt += 1
                continue
            # move value ahead to replace null
            t_idx = v_idx - time_idx_offset
            if null_cnt != 0:
                time[t_idx - null_cnt] = time[t_idx]
                values[v_idx - null_cnt] = values[v_idx]

    def get_data_type(self) -> TSDataType:
        return TSDataType.DOUBLE

ARRAY_SIZE = 10000
TSDataType = enum('DOUBLE', 'INT64')
TSEncoding = enum('RLE', 'TS_2DIFF')

class TimeValuePair:
    def __init__(self, time: int, value: float):
        self.time = time
        self.value = value

class BitMap:

    def is_marked(self, v_idx) -> bool:
        pass

def get_primitive_arrays_by_type(data_type: TSDataType) -> list[float]:
    return [(0.0,) for _ in range(ARRAY_SIZE)]

def check_expansion():
    if len(self.values[-1]) >= ARRAY_SIZE and (len(time) % ARRAY_SIZE != 0):
        self.values.append([time] + [value])
```

Please note that this is a direct translation of the Java code into Python, without considering any performance or best practices.