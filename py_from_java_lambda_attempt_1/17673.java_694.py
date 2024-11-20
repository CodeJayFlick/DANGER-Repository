Here is the translation of the Java code into Python:

```Python
class BinaryTVList:
    def __init__(self):
        self.values = []
        self.sorted_values = None
        self.pivot_value = None
        self.min_time = float('inf')
        self.timestamps = []

    def put_binary(self, timestamp, value):
        if len(self.values) == 0 or (len(self.values[-1]) + 1 >= ARRAY_SIZE and len(self.values) * ARRAY_SIZE < size):
            self.values.append([timestamp])
        else:
            self.values[-1].append(timestamp)
        self.timestamps = [t for t in self.timestamps]
        if timestamp < self.min_time:
            self.min_time = timestamp
        if value is not None:
            return

    def get_binary(self, index):
        array_index = (index // ARRAY_SIZE) - 1
        element_index = index % ARRAY_SIZE
        if len(self.values[array_index]) <= element_index or self.values[array_index][element_index] is None:
            raise ArrayIndexOutOfBoundsException(index)
        return self.values[array_index][element_index]

    def set(self, index, timestamp, value):
        array_index = (index // ARRAY_SIZE) - 1
        element_index = index % ARRAY_SIZE
        if len(self.timestamps[array_index]) <= element_index or self.timestamps[array_index][element_index] is None:
            raise ArrayIndexOutOfBoundsException(index)
        self.timestamps[array_index][element_index] = timestamp
        self.values[array_index][element_index] = value

    def clone(self):
        new_list = BinaryTVList()
        for v in self.values:
            new_list.values.append(v[:])
        return new_list

    def sort(self):
        if not hasattr(self, 'sorted_timestamps'):
            self.sorted_timestamps = [[0]] * (size // ARRAY_SIZE)
        if not hasattr(self, 'sorted_values'):
            self.sorted_values = [[] for _ in range(size // ARRAY_SIZE)]
        self.sort(0, size)
        self.clear_sorted_value()
        self.clear_sorted_time()
        self.__dict__['sorted'] = True

    def clear_value(self):
        for v in self.values:
            PrimitiveArrayManager.release(v)

    def clear_sorted_value(self):
        if hasattr(self, 'sorted_values'):
            del self.sorted_values
        self.__dict__.pop('sorted', None)
        return

    def set_from_sorted(self, src, dest):
        array_index = (dest // ARRAY_SIZE) - 1
        element_index = dest % ARRAY_SIZE
        timestamp = self.timestamps[src // ARRAY_SIZE][src % ARRAY_SIZE]
        value = self.values[src // ARRAY_SIZE][src % ARRAY_SIZE]
        if dest >= size:
            raise ArrayIndexOutOfBoundsException(dest)
        set(dest, timestamp, value)

    def reverse_range(self, lo, hi):
        while lo < hi:
            loT = getTime(lo)
            loV = getBinary(lo)
            hiT = getTime(hi)
            hiV = getBinary(hi)
            self.set(lo++, hiT, hiV)
            set(hi--, loT, loV)

    def expand_values(self):
        if len(self.values) < size // ARRAY_SIZE:
            for _ in range(size // ARRAY_SIZE - len(self.values)):
                self.values.append([0] * ARRAY_SIZE)

    def save_as_pivot(self, pos):
        pivot_time = getTime(pos)
        pivot_value = getBinary(pos)
        return

    def set_pivot_to(self, pos):
        if pos >= size:
            raise ArrayIndexOutOfBoundsException(pos)
        timestamp = self.get_timestamp(pos)
        value = self.get_binary(pos)
        self.set(pos, timestamp, value)

    def timeValuePair(self, index):
        return TimeValuePair(getTime(index), TsPrimitiveType.getByType(TSDataType.TEXT, getBinary(index)))

    def release_last_value_array(self):
        PrimitiveArrayManager.release(self.values.pop())

    def put_binaries(self, time, values, bit_map, start, end):
        if len(time) + (end - start) > size:
            self.check_expansion()
        idx = start
        while idx < end:
            array_index = size // ARRAY_SIZE
            element_index = size % ARRAY_SIZE
            internal_remaining = ARRAY_SIZE - element_index
            input_remaining = end - idx
            if internal_remaining >= input_remaining:
                System.arraycopy(time, idx - time_idx_offset, self.timestamps[array_index], element_index,
                                  input_remaining)
                System.arraycopy(values, idx, self.values[array_index], element_index, input_remaining)
                size += input_remaining
                break
            else:
                System.arraycopy(time, idx - time_idx_offset, self.timestamps[array_index], element_index,
                                  internal_remaining)
                System.arraycopy(values, idx, self.values[array_index], element_index, internal_remaining)
                idx += internal_remaining
                size += internal_remaining

    def drop_null_val_then_update_min_time_and_sorted(self, time, values, bit_map, start, end):
        in_put_min_time = float('inf')
        input_sorted = True
        null_count = 0
        for v_idx in range(start, end):
            if not bit_map.is_marked(v_idx):
                continue
            null_count += 1
            time[v_idx - null_count] = time[v_idx]
            values[v_idx - null_count] = values[v_idx]
        idx = start + null_count
        while idx < end:
            t_idx = idx - time_idx_offset
            if null_count != 0:
                time[t_idx - null_count] = time[t_idx]
                values[indices - null_count] = values[idx]
            in_put_min_time = min(in_put_min_time, time[t_idx])
            input_sorted &= (t_idx > 0 and time[t_idx - 1] <= time[t_idx])
        self.min_time = min(self.min_time, in_put_min_time)
        if not input_sorted:
            sorted = False
        return null_count

    def get_data_type(self):
        return TSDataType.TEXT


class TimeValuePair:
    def __init__(self, timestamp, value):
        self.timestamp = timestamp
        self.value = value

ARRAY_SIZE = 1000
size = 0
time_idx_offset = 0