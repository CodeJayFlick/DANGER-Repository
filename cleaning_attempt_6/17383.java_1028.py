class FirstValueDescAggrResult:
    def __init__(self, data_type):
        pass  # equivalent to super(dataType)

    def update_result_from_statistics(self, statistics):
        first_val = statistics.get_first_value()
        self.set_value(first_val)
        self.timestamp = statistics.get_start_time()

    def update_result_from_page_data(self, batch_iterator, min_bound, max_bound):
        while batch_iterator.has_next() and batch_iterator.current_time() < max_bound and batch_iterator.current_time() >= min_bound:
            self.set_value(batch_iterator.current_value())
            self.timestamp = batch_iterator.current_time()
            batch_iterator.next()

    def update_result_using_timestamps(self, timestamps, length, data_reader):
        values = data_reader.get_values_in_timestamps(timestamps, length)
        for i in range(length - 1, -1, -1):
            if values[i] is not None:
                self.set_value(values[i])
                self.timestamp = timestamps[i]
                return

    def update_result_using_values(self, timestamps, length, values):
        for i in range(length - 1, -1, -1):
            if values[i] is not None:
                self.set_value(values[i])
                self.timestamp = timestamps[i]
                return

    def has_final_result(self):
        return False
