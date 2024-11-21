Here is the translation of the given Java code into Python:

```Python
class ExtremeAggrResult:
    def __init__(self, data_type):
        self.timestamp = float('-inf')
        super().__init__(data_type, 'EXTREME')

    def get_abs_value(self, v):
        if isinstance(v, (int, float)):
            return abs(v)
        else:
            raise ValueError(f"Unsupported data type: {type(v)}")

    def get_extreme_value(self, ext_val, current_val):
        if current_val is not None:
            abs_current_val = self.get_abs_value(current_val)
            if ext_val is None or (abs(ext_val) < abs_current_val and ext_val != current_val):
                return current_val
            else:
                return ext_val
        else:
            return ext_val

    def get_result(self):
        if self.has_candidate_result():
            return self.get_value()
        else:
            return None

    def update_result_from_statistics(self, statistics):
        max_val = statistics['max']
        min_val = statistics['min']

        abs_max_val = self.get_abs_value(max_val)
        abs_min_val = self.get_abs_value(min_val)

        if abs_max_val >= abs_min_val:
            return max_val
        else:
            return min_val

    def update_result_from_page_data(self, batch_iterator):
        self.update_result_from_page_data(batch_iterator, float('-inf'), float('inf'))

    def update_result_from_page_data(self, batch_iterator, min_bound, max_bound):
        ext_val = None

        while batch_iterator.has_next() and batch_iterator.current_time() < max_bound and batch_iterator.current_time() >= min_bound:
            ext_val = self.get_extreme_value(ext_val, batch_iterator.current_value())
            batch_iterator.next()

        if ext_val is not None:
            return ext_val
        else:
            return None

    def update_result_using_timestamps(self, timestamps, length, data_reader):
        raise NotImplementedError("This method should be implemented")

    def update_result_using_values(self, timestamps, length, values):
        for i in range(length):
            self.get_extreme_value(None, values[i])

    def has_final_result(self):
        return False

    def merge(self, another):
        if another.has_candidate_result():
            self.update_result(another.get_result())

    def deserialize_specific_fields(self, buffer):
        self.timestamp = buffer.read_long()

    def serialize_specific_fields(self, output_stream):
        ReadWriteIOUtils.write(self.timestamp, output_stream)

    def update_result(self, ext_val):
        if ext_val is None:
            return

        abs_ext_val = self.get_abs_value(ext_val)
        candidate_result = self.get_value()
        abs_candidate_result = self.get_abs_value(candidate_result)

        if not self.has_candidate_result() or (abs_ext_val > abs_candidate_result and ext_val != candidate_result):
            self.set_value(ext_val)
```

Please note that this is a direct translation of the Java code into Python, without considering any specific Python best practices.