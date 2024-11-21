Here is the translation of the Java code to Python:

```Python
class FillQueryExecutor:
    def __init__(self, fill_query_plan):
        self.plan = fill_query_plan
        self.selected_series = list(self.plan.get_deduplicated_paths())
        self.data_types = list(self.plan.get_deduplicated_data_types())
        self.type_ifill_map = dict(zip(self.data_types, [None] * len(self.data_types)))
        for i in range(len(self.data_types)):
            if self.plan.get_fill_type()[i]:
                self.type_ifill_map[self.data_types[i]] = PreviousFill(self.data_types[i], self.plan.get_query_time(), IoTDBDescriptor.getInstance().get_config().get_default_fill_interval())
        self.query_time = self.plan.get_query_time()

    def execute(self, query_context):
        record = RowRecord(self.query_time)

        storage_group_processors = StorageEngine.getInstance().merge_lock(list(map(PartialPath.from_string, self.selected_series)))
        try:
            time_value_pairs = self.get_time_value_pairs(query_context)
            for i in range(len(self.selected_series)):
                path = PartialPath.from_string(self.selected_series[i])
                data_type = self.data_types[i]

                if time_value_pairs[i] is not None:
                    record.add_field(time_value_pairs[i].get_value().get_value(), data_type)
                    continue

                fill = self.type_ifill_map.get(data_type, PreviousFill(data_type, self.query_time, IoTDBDescriptor.getInstance().get_config().get_default_fill_interval()))
                configured_fill = self.configure_fill(fill, path, data_type, self.query_time, set(self.plan.get_all_measurements_in_device(path.get_device())), query_context)
                time_value_pair = configured_fill.get_fill_result()
                if time_value_pair is None or time_value_pair.get_value() is None:
                    record.add_field(None)
                else:
                    record.add_field(time_value_pair.get_value().get_value(), data_type)

        finally:
            StorageEngine.getInstance().merge_unlock(storage_group_processors)

        single_data_set = SingleDataSet(self.selected_series, self.data_types)
        single_data_set.set_record(record)
        return single_data_set

    def configure_fill(self, fill, path, data_type, query_time, device_measurements, context):
        fill.configure_fill(path, data_type, query_time, device_measurements, context)
        return fill

    def get_time_value_pairs(self, query_context):
        readers = self.init_managed_series_reader(query_context)
        ret = []
        for reader in readers:
            if reader.has_next_batch():
                batch_data = reader.next_batch()
                if batch_data.has_current():
                    ret.append(TimeValuePair(batch_data.get_current_time(), batch_data.get_current_ts_primitive_type()))
                    continue
            ret.append(None)

        return ret

    def init_managed_series_reader(self, query_context):
        time_filter = TimeFilter.eq(self.query_time)
        readers = []
        for i in range(len(self.selected_series)):
            path = PartialPath.from_string(self.selected_series[i])
            data_type = self.data_types[i]
            query_data_source = QueryResourceManager.getInstance().get_query_data_source(path, query_context, time_filter)
            time_filter = query_data_source.update_filter_using_ttl(time_filter)
            reader = SeriesRawDataBatchReader(
                path,
                set(self.plan.get_all_measurements_in_device(path.get_device())),
                data_type,
                query_context,
                query_data_source,
                time_filter,
                None,
                None,
                self.plan.is_ascending()
            )
            readers.append(reader)

        return readers


class RowRecord:
    def __init__(self, query_time):
        self.fields = []

    def add_field(self, value, data_type):
        self.fields.append((value, data_type))


class TimeValuePair:
    def __init__(self, time_value, ts_primitive_type):
        self.time_value = time_value
        self.ts_primitive_type = ts_primitive_type

    def get_time(self):
        return self.time_value

    def get_ts_primitive_type(self):
        return self.ts_primitive_type


class SingleDataSet:
    def __init__(self, selected_series, data_types):
        self.selected_series = selected_series
        self.data_types = data_types
        self.record = RowRecord(0)

    def set_record(self, record):
        self.record = record

    def get_selected_series(self):
        return self.selected_series


class PreviousFill:
    def __init__(self, data_type, query_time, default_fill_interval):
        self.data_type = data_type
        self.query_time = query_time
        self.default_fill_interval = default_fill_interval

    def configure_fill(self, path, data_type, query_time, device_measurements, context):
        pass  # No implementation for this method in the original code


class StorageEngine:
    instance = None

    @classmethod
    def getInstance(cls):
        if cls.instance is None:
            cls.instance = StorageEngine()
        return cls.instance

    def merge_lock(self, selected_series):
        pass  # No implementation for this method in the original code

    def merge_unlock(self, storage_group_processors):
        pass  # No implementation for this method in the original code


class IoTDBDescriptor:
    instance = None
    config = None

    @classmethod
    def getInstance(cls):
        if cls.instance is None:
            cls.instance = IoTDBDescriptor()
        return cls.instance

    def get_config(self):
        return self.config


# Usage example:

fill_query_plan = FillQueryPlan()  # Initialize the fill query plan object
executor = FillQueryExecutor(fill_query_plan)
query_context = QueryContext()  # Initialize the query context object
data_set = executor.execute(query_context)  # Execute the fill query and get the result
```

Please note that this is a direct translation of your Java code to Python, without considering any potential issues or improvements.