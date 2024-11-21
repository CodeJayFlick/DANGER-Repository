class MaxTimeAggrResult:
    def __init__(self):
        self.ts_data_type = 'INT64'
        self.aggregation_type = 'MAX_TIME'
        self.reset()

    @property
    def result(self):
        if self.has_candidate_result():
            return self.long_value
        else:
            return None

    def update_result_from_statistics(self, statistics):
        max_timestamp = statistics.get_end_time()
        self.update_max_time_result(max_timestamp)

    def update_result_from_page_data(self, batch_iterator):
        self.update_result_from_page_data(batch_iterator, float('-inf'), float('inf'))

    def update_result_from_page_data(self, batch_iterator, min_bound, max_bound):
        while batch_iterator.has_next() and batch_iterator.current_time < max_bound and batch_iterator.current_time >= min_bound:
            self.update_max_time_result(batch_iterator.current_time)
            batch_iterator.next()

    def update_result_using_timestamps(self, timestamps, length, data_reader):
        values = data_reader.get_values_in_timestamps(timestamps, length)
        for i in range(length - 1, -1, -1):
            if values[i] is not None:
                self.update_max_time_result(timestamps[i])
                return

    def update_result_using_values(self, timestamps, length, values):
        for i in range(length - 1, -1, -1):
            if values[i] is not None:
                self.update_max_time_result(timestamps[i])
                return

    @property
    def has_final_result(self):
        return False

    def merge(self, another):
        another = MaxTimeAggrResult(another)
        if another.result is not None:
            self.update_max_time_result(another.result)

    def deserialize_specific_fields(self, buffer): pass

    def serialize_specific_fields(self, output_stream): pass

    def update_max_time_result(self, value):
        if not self.has_candidate_result() or value >= self.long_value:
            self.long_value = value
