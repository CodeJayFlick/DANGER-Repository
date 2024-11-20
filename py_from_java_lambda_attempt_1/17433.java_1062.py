Here is the translation of the given Java code into Python:

```Python
class PreviousFill:
    def __init__(self, data_type: str, query_time: int, before_range: int):
        self.data_type = data_type
        self.query_time = query_time
        self.before_range = before_range

    @property
    def until_last(self) -> bool:
        return self._until_last

    @until_last.setter
    def until_last(self, value: bool):
        self._until_last = value

    def copy(self) -> 'PreviousFill':
        return PreviousFill(self.data_type, self.query_time, self.before_range, self.until_last)

    def construct_filter(self):
        lower_bound = None
        if self.before_range == -1:
            lower_bound = TimeFilter.gte(Long.MIN_VALUE)
        else:
            lower_bound = TimeFilter.gte(self.query_time - self.before_range)
        time_filter = FilterFactory.and(lower_bound, TimeFilter.lte(self.query_time))
        return time_filter

    def get_before_range(self) -> int:
        return self.before_range

    def configure_fill(
        self,
        path: str,
        data_type: str,
        query_time: int,
        sensors: set[str],
        context: dict
    ):
        self.path = path
        self.data_type = data_type
        self.context = context
        self.query_time = query_time
        self.sensors = sensors

    def get_fill_result(self) -> tuple:
        time_filter = construct_filter()
        last_reader = LastPointReader(
            series_path=self.path,
            data_type=self.data_type,
            all_sensors=self.sensors,
            context=self.context,
            query_time=self.query_time,
            time_filter=time_filter
        )
        return last_reader.read_last_point()

class TimeFilter:
    @staticmethod
    def gte(value: int) -> 'TimeFilter':
        # implementation

    @staticmethod
    def lte(value: int) -> 'TimeFilter':
        # implementation


class FilterFactory:
    @staticmethod
    def and(*filters: list['TimeFilter']) -> 'Filter':
        # implementation


class LastPointReader:
    def __init__(self, series_path: str, data_type: str, all_sensors: set[str], context: dict, query_time: int, time_filter):
        self.series_path = series_path
        self.data_type = data_type
        self.all_sensors = all_sensors
        self.context = context
        self.query_time = query_time
        self.time_filter = time_filter

    def read_last_point(self) -> tuple:
        # implementation


class Long(int):
    MIN_VALUE = -9223372036854775808
```

Note that this is a direct translation of the Java code into Python, and it may not be perfect. The `Long` class in Java does not have an equivalent in Python (since Python's integers are arbitrary-precision), so I used the built-in integer type instead.