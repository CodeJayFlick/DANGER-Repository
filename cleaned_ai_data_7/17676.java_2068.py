class FloatTVList:
    def __init__(self):
        self.values = []
        self.sorted_values = None
        self.pivot_value = None

    def put_float(self, timestamp: int, value: float) -> None:
        if len(self.values) < (timestamp // 8 + 1):
            self.values.append([0.0] * 8)
        array_index = timestamp // 8
        element_index = timestamp % 8
        min_time = min(min_time, timestamp) if hasattr(self, 'min_time') else timestamp
        timestamps[array_index][element_index] = timestamp
        values[array_index][element_index] = value
        size += 1

    def get_float(self, index: int) -> float:
        if index >= self.size:
            raise IndexError(index)
        array_index = index // 8
        element_index = index % 8
        return values[array_index][element_index]

    def set(self, index: int, timestamp: int, value: float) -> None:
        if index >= self.size:
            raise IndexError(index)
        array_index = index // 8
        element_index = index % 8
        timestamps[array_index][element_index] = timestamp
        values[array_index][element_index] = value

    def clone(self) -> 'FloatTVList':
        clone_list = FloatTVList()
        for v in self.values:
            clone_list.values.append(v[:])
        return clone_list

    def sort(self) -> None:
        if not hasattr(self, 'sorted_timestamps') or len(self.sorted_timestamps) < self.size:
            sorted_timestamps = [(0,) * 8] * (self.size // 8 + 1)
            for i in range(len(sorted_timestamps)):
                sorted_timestamps[i][:] = timestamps[i]
        if not hasattr(self, 'sorted_values') or len(self.sorted_values) < self.size:
            sorted_values = [[0.0] * 8] * (self.size // 8 + 1)
            for i in range(len(sorted_values)):
                sorted_values[i][:] = values[i]
        sort(0, self.size - 1)

    def clear_value(self) -> None:
        if hasattr(self, 'values'):
            del self.values[:]
            self.values.clear()

    def set_from_sorted(self, src: int, dest: int) -> None:
        set(dest, sorted_timestamps[src // 8][src % 8], sorted_values[src // 8][src % 8])

    def release_last_value_array(self) -> None:
        del self.values[-1]

    def put_floats(self, time: list[int], value: list[float], bit_map: 'BitMap', start: int, end: int) -> None:
        if len(time) + (end - start) > 8 * (self.size // 8 + 1):
            self.values.append([0.0] * 8)
        idx = start
        time_idx_offset = 0
        if bit_map and not bit_map.is_all_unmarked():
            cloned_time = [t for t in time]
            system_array_copy(cloned_time, start, end - start)
            time = cloned_time
            time_idx_offset = start
            null_count = drop_null_val_then_update_min_time_and_sorted(time, value, bit_map, start, end, time_idx_offset)
            end -= null_count

        while idx < end:
            input_remaining = end - idx
            array_index = self.size // 8
            element_index = self.size % 8
            internal_remaining = 8 - element_index
            if internal_remaining >= input_remaining:
                system_array_copy(time, idx - time_idx_offset, timestamps[array_index], element_index, input_remaining)
                system_array_copy(value, idx, values[array_index], element_index, input_remaining)
                self.size += input_remaining
                break

    def drop_null_val_then_update_min_time_and_sorted(self, time: list[int], value: list[float], bit_map: 'BitMap', start: int, end: int, t_idx_offset: int) -> int:
        in_put_min_time = float('inf')
        input_sorted = True
        null_count = 0

        for v_idx in range(start, end):
            if bit_map.is_marked(v_idx):
                null_count += 1
                continue
            # move value ahead to replace null
            t_idx = v_idx - t_idx_offset
            if null_count != 0:
                time[t_idx - null_count] = time[t_idx]
                values[v_idx - null_count] = values[v_idx]

        min_time = min(min_time, in_put_min_time) if hasattr(self, 'min_time') else in_put_min_time

    def get_data_type(self) -> int:
        return 0
