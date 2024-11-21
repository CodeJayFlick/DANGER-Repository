Here is the translation of the given Java code into Python:

```Python
class MaxValueAggrResult:
    def __init__(self, data_type):
        self.data_type = data_type
        self.aggregation_type = 'MAX_VALUE'
        self.reset()

    def get_result(self):
        if self.has_candidate_result():
            return self.get_value()
        else:
            return None

    def update_result_from_statistics(self, statistics):
        max_val = statistics.max_value
        self.update_result(max_val)

    def update_result_from_page_data(self, batch_iterator):
        min_bound = long('-inf')
        max_bound = long('inf')

        while batch_iterator.has_next() and batch_iterator.current_time < max_bound and batch_iterator.current_time >= min_bound:
            if not hasattr(self, 'max_val') or self.max_val < batch_iterator.current_value:
                self.max_val = batch_iterator.current_value
            batch_iterator.next()

        self.update_result(self.max_val)

    def update_result_from_page_data_with_bounds(self, batch_iterator, min_bound, max_bound):
        self.max_val = None

        while batch_iterator.has_next() and batch_iterator.current_time < max_bound and batch_iterator.current_time >= min_bound:
            if not hasattr(self, 'max_val') or self.max_val < batch_iterator.current_value:
                self.max_val = batch_iterator.current_value
            batch_iterator.next()

        self.update_result(self.max_val)

    def update_result_using_timestamps(self, timestamps, length, data_reader):
        max_val = None

        values = [data_reader.get_values_in_timestamps(timestamps[i], 1)[0] for i in range(length)]

        for value in values:
            if value is not None and (max_val is None or max_val < value):
                max_val = value
        self.update_result(max_val)

    def update_result_using_values(self, timestamps, length, values):
        max_val = None

        for i in range(length):
            if values[i] is not None and (max_val is None or max_val < values[i]):
                max_val = values[i]
        self.update_result(max_val)

    def has_final_result(self):
        return False

    def merge(self, another):
        self.update_result(another.get_result())

    def deserialize_specific_fields(self, buffer): pass
    def serialize_specific_fields(self, output_stream): pass

    def update_result(self, max_val):
        if max_val is None:
            return
        if not self.has_candidate_result() or max_val > self.get_value():
            self.set_value(max_val)
```

Please note that Python does not have direct equivalent of Java's Comparable interface. In the above code, I've used Python's built-in comparison operators to compare values. Also, in some places where Java uses `Comparable` type parameters, I've simply removed them as they are not necessary in Python.