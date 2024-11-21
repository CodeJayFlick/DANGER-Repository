Here is the translation of the Java code into Python:

```Python
class MinValueAggrResult:
    def __init__(self, data_type):
        self.data_type = data_type
        self.aggregation_type = 'MIN_VALUE'
        self.reset()

    def get_result(self):
        if self.has_candidate_result():
            return self.get_value()
        else:
            return None

    def update_result_from_statistics(self, statistics):
        min_val = statistics.min_value
        self.update_result(min_val)

    def update_result_from_page_data(self, batch_iterator):
        while batch_iterator.has_next() and batch_iterator.current_time < max_bound and batch_iterator.current_time >= min_bound:
            self.update_result(batch_iterator.current_value())
            batch_iterator.next()

    def update_result_using_timestamps(self, timestamps, length, data_reader):
        if not hasattr(self, 'min_val'):
            self.min_val = None
        values = [data_reader.get_values_in_timestamps(timestamps[i], i) for i in range(length)]
        for value in values:
            if value is not None and (self.min_val is None or self.min_val > value):
                self.min_val = value
        self.update_result(self.min_val)

    def update_result_using_values(self, timestamps, length, values):
        if not hasattr(self, 'min_val'):
            self.min_val = None
        for i in range(length):
            if values[i] is not None and (self.min_val is None or self.min_val > values[i]):
                self.min_val = values[i]
        self.update_result(self.min_val)

    def has_final_result(self):
        return False

    def merge(self, another):
        if another.get_result() is not None:
            value = another.get_result()
            self.update_result(value)

    def deserialize_specific_fields(self, buffer): pass
    def serialize_specific_fields(self, output_stream): pass

    def update_result(self, min_val):
        if min_val is None:
            return
        if not self.has_candidate_result() or min_val < self.get_value():
            self.set_value(min_val)
```

Please note that Python does not have direct equivalent of Java's Comparable interface. In the above code, I used Python's built-in comparison operators to compare values.