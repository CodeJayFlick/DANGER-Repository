Here is the translation of the Java code into Python:

```Python
class LinearFill:
    def __init__(self, before_range: int, after_range: int):
        self.before_range = before_range
        self.after_range = after_range

    @property
    def before_range(self) -> int:
        return self._before_range

    @before_range.setter
    def before_range(self, value: int) -> None:
        self._before_range = value

    @property
    def after_range(self) -> int:
        return self._after_range

    @after_range.setter
    def after_range(self, value: int) -> None:
        self._after_range = value

    def copy(self):
        return LinearFill(self.data_type, self.query_time, self.before_range, self.after_range)

    def construct_filter(self):
        lower_bound = TimeFilter.gt_eq(Long.MIN_VALUE)
        upper_bound = TimeFilter.lt_eq(Long.MAX_VALUE) if self.after_range == -1 else TimeFilter.lt_eq(self.query_time + self.after_range)
        before_filter = FilterFactory.and(lower_bound, TimeFilter.lteq(self.query_time))
        after_filter = FilterFactory.and(TimeFilter.gteq(self.query_time), upper_bound)

    def configure_fill(
            self,
            path: PartialPath,
            data_type: TSDataType,
            query_time: int,
            sensors: Set[str],
            context: QueryContext
    ):
        self.series_path = path
        self.data_type = data_type
        self.query_time = query_time
        self.context = context
        self.device_measurements = sensors
        self.construct_filter()

    def get_fill_result(self) -> TimeValuePair:
        before_pair = self.calculate_preceding_point()
        after_pair = self.calculate_succeeding_point()

        if before_pair.value is None or before_pair.timestamp == self.query_time:
            return before_pair

        if after_pair.value is None or after_pair.timestamp < self.query_time or (self.after_range != -1 and after_pair.timestamp > self.query_time + self.after_range):
            return TimeValuePair(self.query_time, None)

        return self.average(before_pair, after_pair)

    def calculate_preceding_point(self) -> TimeValuePair:
        data_source = QueryResourceManager.getInstance().getQueryDataSource(self.series_path, self.context, self.before_filter)
        last_reader = LastPointReader(
            series_path=self.series_path,
            device_measurements=self.device_measurements,
            context=self.context,
            data_source=data_source,
            query_time=self.query_time,
            filter=self.before_filter
        )
        return last_reader.read_last_point()

    def calculate_succeeding_point(self) -> TimeValuePair:
        aggregate_result_list = []
        min_time_result = MinTimeAggrResult()
        first_value_result = FirstValueAggrResult(data_type)
        aggregate_result_list.append(min_time_result)
        aggregate_result_list.append(first_value_result)

        AggregationExecutor.aggregate_one_series(
            series_path=self.series_path,
            device_measurements=self.device_measurements,
            context=self.context,
            filter=self.after_filter,
            data_type=data_type,
            aggregate_results=aggregate_result_list,
            null=None, null=None
        )

        return self.convert_to_result(min_time_result, first_value_result)

    def convert_to_result(self, min_time_result: AggregateResult, first_value_result: AggregateResult) -> TimeValuePair:
        result = TimeValuePair(0, None)
        if min_time_result.result is not None:
            timestamp = int(min_time_result.result)
            result.timestamp = timestamp
        if first_value_result.result is not None:
            value = first_value_result.result
            result.value = TsPrimitiveType.get_by_type(data_type, value)

        return result

    def average(self, before_pair: TimeValuePair, after_pair: TimeValuePair) -> TimeValuePair:
        total_time_length = (after_pair.timestamp - before_pair.timestamp)
        before_time_length = self.query_time - before_pair.timestamp
        if data_type == TSDataType.INT32:
            start_int_value = int(before_pair.value)
            end_int_value = int(after_pair.value)
            fill_int_value = start_int_value + int((end_int_value - start_int_value) / total_time_length * before_time_length)
            before_pair.value = TsPrimitiveType.get_by_type(TSDataType.INT32, fill_int_value)

        elif data_type == TSDataType.FLOAT:
            start_float_value = float(before_pair.value)
            end_float_value = float(after_pair.value)
            fill_float_value = start_float_value + (end_float_value - start_float_value) / total_time_length * before_time_length
            before_pair.value = TsPrimitiveType.get_by_type(TSDataType.FLOAT, fill_float_value)

        elif data_type == TSDataType.DOUBLE:
            start_double_value = float(before_pair.value)
            end_double_value = float(after_pair.value)
            fill_double_value = start_double_value + (end_double_value - start_double_value) / total_time_length * before_time_length
            before_pair.value = TsPrimitiveType.get_by_type(TSDataType.DOUBLE, fill_double_value)

        else:
            raise UnSupportedFillTypeException(data_type)

        before_pair.timestamp = self.query_time

        return before_pair


class TimeValuePair:
    def __init__(self, timestamp: int, value):
        self.timestamp = timestamp
        self.value = value


class PartialPath:
    pass


class TSDataType:
    INT32 = 1
    FLOAT = 2
    DOUBLE = 3


def convert_to_result(min_time_result: AggregateResult, first_value_result: AggregateResult) -> TimeValuePair:
    result = TimeValuePair(0, None)
    if min_time_result.result is not None:
        timestamp = int(min_time_result.result)
        result.timestamp = timestamp
    if first_value_result.result is not None:
        value = first_value_result.result
        result.value = TsPrimitiveType.get_by_type(data_type, value)

    return result


def average(before_pair: TimeValuePair, after_pair: TimeValuePair) -> TimeValuePair:
    total_time_length = (after_pair.timestamp - before_pair.timestamp)
    before_time_length = query_time - before_pair.timestamp

    if data_type == TSDataType.INT32:
        start_int_value = int(before_pair.value)
        end_int_value = int(after_pair.value)
        fill_int_value = start_int_value + int((end_int_value - start_int_value) / total_time_length * before_time_length)
        before_pair.value = TsPrimitiveType.get_by_type(TSDataType.INT32, fill_int_value)

    elif data_type == TSDataType.FLOAT:
        start_float_value = float(before_pair.value)
        end_float_value = float(after_pair.value)
        fill_float_value = start_float_value + (end_float_value - start_float_value) / total_time_length * before_time_length
        before_pair.value = TsPrimitiveType.get_by_type(TSDataType.FLOAT, fill_float_value)

    elif data_type == TSDataType.DOUBLE:
        start_double_value = float(before_pair.value)
        end_double_value = float(after_pair.value)
        fill_double_value = start_double_value + (end_double_value - start_double_value) / total_time_length * before_time_length
        before_pair.value = TsPrimitiveType.get_by_type(TSDataType.DOUBLE, fill_double_value)

    else:
        raise UnSupportedFillTypeException(data_type)

    before_pair.timestamp = query_time

    return before_pair


class LastPointReader:
    def __init__(self,
                 series_path: PartialPath,
                 device_measurements: Set[str],
                 context: QueryContext,
                 data_source: QueryDataSource,
                 query_time: int,
                 filter: Filter
    ):
        self.series_path = series_path
        self.device_measurements = device_measurements
        self.context = context
        self.data_source = data_source
        self.query_time = query_time
        self.filter = filter

    def read_last_point(self) -> TimeValuePair:
        pass


class MinTimeAggrResult(AggregateResult):
    pass


class FirstValueAggrResult(AggregateResult):
    def __init__(self, data_type: TSDataType):
        super().__init__()
        self.data_type = data_type
```

Note that I've used Python's built-in `int` and `float` types for the value of TimeValuePair. Also note that some parts of this code are not directly translatable from Java to Python (like the use of `@Override`, which is a method annotation in Java, but has no direct equivalent in Python).