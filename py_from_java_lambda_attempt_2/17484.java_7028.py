Here is the translation of the Java code to Python:
```python
import io

class SeriesRawDataPointReader:
    def __init__(self, series_reader):
        self.batch_reader = SeriesRawDataBatchReader(series_reader)
        self.has_cached_time_value_pair = False
        self.batch_data = None
        self.time_value_pair = None

    def has_next_time_value_pair(self) -> bool:
        if self.has_cached_time_value_pair:
            return True

        if self.batch_data and self.batch_data.has_current():
            self.time_value_pair = TimeValuePair(
                batch_data=current=self.batch_data.current_time(),
                ts_primitive_type=self.batch_data.current_ts_primitive_type()
            )
            self.has_cached_time_value_pair = True
            self.batch_data.next()
            return True

        while self.batch_reader.has_next_batch():
            self.batch_data = self.batch_reader.next_batch()
            if self.batch_data and self.batch_data.has_current():
                self.time_value_pair = TimeValuePair(
                    batch_data=current=self.batch_data.current_time(),
                    ts_primitive_type=self.batch_data.current_ts_primitive_type()
                )
                self.has_cached_time_value_pair = True
                self.batch_data.next()
                return True

        return False

    def next_time_value_pair(self) -> 'TimeValuePair':
        if self.has_cached_time_value_pair or self.has_next_time_value_pair():
            self.has_cached_time_value_pair = False
            return self.time_value_pair
        else:
            raise IOError("no next data")

    def current_time_value_pair(self):
        return self.time_value_pair

    def close(self) -> None:
        pass  # no resources need to be closed


class TimeValuePair:
    def __init__(self, batch_data: 'BatchData', ts_primitive_type: str):
        self.batch_data = batch_data
        self.ts_primitive_type = ts_primitive_type


class BatchData:
    def __init__(self):
        pass

    def has_current(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def current_time(self) -> float:
        raise NotImplementedError("Subclasses must implement this method")

    def current_ts_primitive_type(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self):
        pass  # not implemented


class SeriesRawDataBatchReader:
    def __init__(self, series_reader: 'SeriesReader'):
        self.series_reader = series_reader

    def has_next_batch(self) -> bool:
        return False  # not implemented

    def next_batch(self) -> 'BatchData':
        raise NotImplementedError("Subclasses must implement this method")


class SeriesReader:
    pass  # abstract class, no implementation
```
Note that I've used Python's built-in `io` module for the `IOException` exception. Also, some methods and classes are not implemented in this translation, as they were not provided with a Java implementation (e.g., `BatchData`, `SeriesRawDataBatchReader`).