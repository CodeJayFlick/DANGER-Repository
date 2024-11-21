class LongTVList:
    def __init__(self):
        self.values = []
        self.sorted_values = None
        self.pivot_value = 0
        self.min_time = float('inf')

    def put_long(self, timestamp: int, value: int) -> None:
        if len(self.values) == (len(self.timestamps) + 1) // ARRAY_SIZE:
            self.check_expansion()
        array_index = len(self.values) // ARRAY_SIZE
        element_index = len(self.values) % ARRAY_SIZE
        self.min_time = min(self.min_time, timestamp)
        self.timestamps.append(timestamp)
        self.values.append([timestamp, value])
        if sorted and (len(self.values) > 1 and timestamp < self.get_long(len(self.values) - 2)):
            self.sorted = False

    def get_long(self, index: int) -> int:
        if index >= len(self.values):
            raise IndexError(index)
        array_index = index // ARRAY_SIZE
        element_index = index % ARRAY_SIZE
        return self.values[array_index][element_index]

    def set(self, index: int, timestamp: int, value: int) -> None:
        if index >= len(self.values):
            raise IndexError(index)
        array_index = index // ARRAY_SIZE
        element_index = index % ARRAY_SIZE
        self.timestamps[array_index].append(timestamp)
        self.values[array_index][element_index] = [timestamp, value]

    def clone(self) -> 'LongTVList':
        new_list = LongTVList()
        for i in range(len(self.values)):
            new_list.values.append([self.get_long(i), 0])
        return new_list

    def sort(self):
        if self.sorted_timestamps is None or len(self.sorted_timestamps) < len(self.timestamps):
            self.sorted_timestamps = [[i] for i in range(1, ARRAY_SIZE + 1)]
        if self.sorted_values is None or len(self.sorted_values) < len(self.values):
            self.sorted_values = [[0]] * (len(self.values))
        self.sort(0, len(self.values))
        self.clear_sorted_value()
        self.clear_sorted_time()
        self.sorted = True

    def clear_value(self) -> None:
        if self.values is not None:
            for i in range(len(self.values)):
                del self.values[i]
            self.values = []

    def get_primitive_arrays_by_type(self, data_type: int):
        return [[i] for i in range(1, ARRAY_SIZE + 1)]

    def expand_values(self) -> None:
        self.values.append([0])

    def save_as_pivot(self, pos: int) -> None:
        self.pivot_time = self.get_long(pos)
        self.pivot_value = [self.get_long(pos), 0]

    def set_pivot_to(self, pos: int):
        self.set(pos, *self.pivot_value)

    def get_timeValuePair(self, index: int) -> tuple[int, int]:
        return (self.get_long(index), TsPrimitiveType.get_by_type(TSDataType.INT64, self.get_long(index)))

    def release_last_value_array(self) -> None:
        del self.values[-1]

    def putLongs(self, time: list[int], value: list[int], bit_map: BitMap, start: int, end: int):
        if len(time) + (end - start) > ARRAY_SIZE:
            self.check_expansion()
        idx = start
        for i in range(start, end):
            if not bit_map.is_marked(i):
                time[i] += 1

    def drop_null_val_then_update_min_time_and_sorted(self, time: list[int], values: list[list[int]], bit_map: BitMap, start: int, end: int) -> None:
        in_put_min_time = float('inf')
        input_sorted = True
        null_count = 0
        for i in range(start, end):
            if not bit_map.is_marked(i):
                time[i] += 1

    def get_data_type(self) -> TSDataType:
        return TSDataType.INT64


class BitMap:

    def is_all_unmarked(self) -> bool:
        pass

    def is_marked(self, index: int) -> bool:
        pass
