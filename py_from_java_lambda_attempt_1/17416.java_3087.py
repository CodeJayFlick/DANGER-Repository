Here is the translation of the Java code into Python:

```Python
class RawQueryDataSetWithValueFilter:
    def __init__(self,
                 paths: list[PartialPath],
                 data_types: list[TSDataType],
                 time_generator: TimeGenerator,
                 readers: list[IReaderByTimestamp],
                 cached: list[bool],
                 ascending: bool):
        super().__init__([], data_types, ascending)
        self.time_generator = time_generator
        self.series_reader_by_timestamp_list = readers
        self.cached = cached

    def hasNext_without_constraint(self) -> bool:
        if not self.cached_row_records:
            return cache_row_records()
        return True

    def next_without_constraint(self) -> RowRecord | None:
        if not self.cached_row_records and not cache_row_records():
            return None
        row_record = self.cached_row_records.pop(-1)
        return row_record

    def cache_row_records(self) -> bool:
        cached_time_array = [0] * fetch_size
        time_generator_index = 0
        while time_generator.has_next() and time_generator_index < fetch_size:
            cached_time_array[time_generator_index] = time_generator.next()
            time_generator_index += 1

        if not any(cached_time_array):
            return False

        row_records = [RowRecord(0) for _ in range(time_generator_index)]
        has_field = [False] * time_generator_index
        for i, reader_by_timestamp in enumerate(self.series_reader_by_timestamp_list):
            results = []
            if cached[i]:
                results = time_generator.get_values(paths[i])
            else:
                results = reader_by_timestamp.get_values_in_timestamps(cached_time_array, time_generator_index)

            for j, result in enumerate(results):
                row_records[j].add_field(result)
        for i in range(time_generator_index - 1, -1, -1):
            if has_field[i]:
                self.cached_row_records.append(row_records[i])

        return not self.cached_row_records

    def hasNextRowInObjects(self) -> bool:
        if not self.cached_row_in_objects:
            return cache_row_in_objects()
        return True

    def nextRowInObjects(self) -> list[object] | None:
        if not self.cached_row_in_objects and not cache_row_in_objects():
            return [0 for _ in range(len(self.series_reader_by_timestamp_list))]
        row_object = self.cached_row_in_objects.pop(-1)
        return row_object

    def cacheRowInObjects(self) -> bool:
        cached_time_array = [0] * fetch_size
        time_generator_index = 0
        while time_generator.has_next() and time_generator_index < fetch_size:
            cached_time_array[time_generator_index] = time_generator.next()
            time_generator_index += 1

        if not any(cached_time_array):
            return False

        rows_in_object = [[None for _ in range(len(self.series_reader_by_timestamp_list) + 1)] for _ in
                          range(time_generator_index)]
        has_field = [False] * time_generator_index
        for i, reader_by_timestamp in enumerate(self.series_reader_by_timestamp_list):
            results = []
            if cached[i]:
                results = time_generator.get_values(paths[i])
            else:
                results = reader_by_timestamp.get_values_in_timestamps(cached_time_array, time_generator_index)

            for j, result in enumerate(results):
                rows_in_object[j][i] = result
        for i in range(time_generator_index - 1, -1, -1):
            if has_field[i]:
                self.cached_row_in_objects.append(rows_in_object[i])

        return not self.cached_row_in_objects

    def cacheRowRecords(self) -> bool:
        # TODO: LIMIT constraint
        cached_time_array = [0] * fetch_size
        time_generator_index = 0
        while time_generator.has_next() and time_generator_index < fetch_size:
            cached_time_array[time_generator_index] = time_generator.next()
            time_generator_index += 1

        if not any(cached_time_array):
            return False

        row_records = [RowRecord(0) for _ in range(time_generator_index)]
        has_field = [False] * time_generator_index
        for i, reader_by_timestamp in enumerate(self.series_reader_by_timestamp_list):
            results = []
            if cached[i]:
                results = time_generator.get_values(paths[i])
            else:
                results = reader_by_timestamp.get_values_in_timestamps(cached_time_array, time_generator_index)

            for j, result in enumerate(results):
                row_records[j].add_field(result)
        for i in range(time_generator_index - 1, -1, -1):
            if has_field[i]:
                self.cached_row_records.append(row_records[i])

        return not self.cached_row_records
```

Please note that this translation is based on the assumption that `PartialPath`, `TSDataType`, and other types are equivalent to Python's built-in data structures.