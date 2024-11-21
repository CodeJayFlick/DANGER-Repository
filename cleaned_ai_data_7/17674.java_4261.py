class BooleanTVList:
    def __init__(self):
        self.values = []
        self.sorted_values = None
        self.pivot_value = None

    def put_boolean(self, timestamp: int, value: bool) -> None:
        if len(self.values) == 0 or (len(self.values[-1]) + 1 >= ARRAY_SIZE):
            self.values.append([False] * ARRAY_SIZE)
        array_index = len(self.values) - 1
        element_index = len(self.values[array_index])
        min_time = timestamp if not hasattr(self, 'min_time') else min(timestamp, self.min_time)
        timestamps = getattr(self, 'timestamps', [[0]] * (ARRAY_SIZE + 1))
        timestamps[array_index][element_index] = timestamp
        values = getattr(self, 'values', [[] for _ in range(ARRAY_SIZE)])
        values[array_index][element_index] = value
        self.size += 1

    def get_boolean(self, index: int) -> bool:
        if index >= self.size:
            raise IndexError(index)
        array_index = index // ARRAY_SIZE
        element_index = index % ARRAY_SIZE
        return self.values[array_index][element_index]

    def set(self, index: int, timestamp: int, value: bool) -> None:
        if index >= self.size:
            raise IndexError(index)
        array_index = index // ARRAY_SIZE
        element_index = index % ARRAY_SIZE
        timestamps = getattr(self, 'timestamps', [[0]] * (ARRAY_SIZE + 1))
        values = getattr(self, 'values', [[] for _ in range(ARRAY_SIZE)])
        timestamps[array_index][element_index] = timestamp
        values[array_index][element_index] = value

    def clone(self) -> 'BooleanTVList':
        clone_list = BooleanTVList()
        self.clone_as(clone_list)
        for value_array in self.values:
            clone_list.values.append([v.copy() for v in value_array])
        return clone_list

    def sort(self) -> None:
        if not hasattr(self, 'sorted_timestamps'):
            sorted_timestamps = [[0] * ARRAY_SIZE for _ in range(ARRAY_SIZE)]
            setattr(self, 'sorted_timestamps', sorted_timestamps)
        if not hasattr(self, 'sorted_values'):
            sorted_values = [[False] * ARRAY_SIZE for _ in range(ARRAY_SIZE)]
            setattr(self, 'sorted_values', sorted_values)
        self.sort(0, self.size)

    def clear_value(self) -> None:
        if self.values is not None:
            for data_array in self.values:
                PrimitiveArrayManager.release(data_array)
            self.values.clear()

    # ... (rest of the methods are similar to above)
