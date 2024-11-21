Here is the translation of the given Java code into Python:

```Python
class SumAggrResult:
    def __init__(self, series_data_type):
        self.series_data_type = series_data_type
        self.result = 0.0

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, value):
        self._result = value

    def get_result(self):
        return self.result

    def update_result_from_statistics(self, statistics):
        if isinstance(statistics, (int, bool)):
            self.result += statistics.get_sum_long_value()
        else:
            self.result += statistics.get_sum_double_value()

    def update_result_from_page_data(self, batch_iterator):
        while batch_iterator.has_next():
            value = batch_iterator.current_value()
            self.update_sum(value)
            batch_iterator.next()

    def update_result_using_timestamps(self, timestamps, length, data_reader):
        values = [data_reader.get_values_in_timestamps(timestamps[i], i) for i in range(length)]
        for i in range(len(values)):
            if values[i] is not None:
                self.update_sum(values[i])

    def update_result_using_values(self, timestamps, length, values):
        for i in range(len(values)):
            if values[i] is not None:
                self.update_sum(values[i])

    def update_sum(self, value):
        try:
            if isinstance(value, (int, bool)):
                self.result += int(value)
            elif isinstance(value, float):
                self.result += float(value)
            else:
                raise UnSupportedDataTypeException(f"Unsupported data type in aggregation SUM: {self.series_data_type}")
        except Exception as e:
            print(e)

    def has_final_result(self):
        return False

    def merge(self, another):
        if isinstance(another, SumAggrResult):
            self.result += another.get_result()

    @classmethod
    def deserialize(cls, buffer):
        from tsfile.file.metadata.enums import TSDataType
        series_data_type = TSDataType.deserialize(buffer)
        return cls(series_data_type)

    @classmethod
    def serialize(cls, outputStream):
        ReadWriteIOUtils.write(cls.series_data_type, outputStream)
```

Please note that Python does not have direct equivalent of Java's `TSDataType` and other custom classes. So I've used the built-in types like int, float etc., to represent these data types in this translation.