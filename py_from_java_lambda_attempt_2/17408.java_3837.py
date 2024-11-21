Here is the translation of the Java code to Python:

```Python
class GroupByFillDataSet:
    def __init__(self,
                 paths: list[PartialPath],
                 data_types: list[TSDataType],
                 group_by_engine_data_set: 'GroupByEngineDataSet',
                 fill_types: dict[TSDataType, IFill],
                 query_context: QueryContext,
                 group_by_fill_plan: GroupByTimeFillPlan):
        super().__init__(paths, data_types)
        self.group_by_engine_data_set = group_by_engine_data_set
        self.fill_types = fill_types

    def init_previous_paris(self, context: QueryContext, plan: GroupByTimeFillPlan) -> None:
        previous_values = [None] * len(paths)
        previous_times = [long.MaxValue] * len(paths)
        first_not_null_tvs = [None] * len(paths)

        for i in range(len(paths)):
            path = paths[i]
            data_type = data_types[i]
            fill: IFill
            if data_type in self.fill_types:
                fill = PreviousFill(
                    data_type,
                    group_by_engine_data_set.start_time,
                    (self.fill_types[data_type]).before_range,
                    (self.fill_types[data_type]).is_until_last()
                )
            else:
                fill = PreviousFill(
                    data_type,
                    group_by_engine_data_set.start_time,
                    IoTDBDescriptor.getInstance().getConfig().getDefault_fill_interval
                )

            fill.configure_fill(
                path, 
                data_type, 
                group_by_engine_data_set.start_time, 
                plan.get_all_measurements_in_device(path.device), 
                context
            )
            
            first_not_null_tvs[i] = fill.fill_result()
            previous_values[i] = None
            previous_times[i] = long.MaxValue

    def init_last_time_array(self, context: QueryContext, plan: GroupByTimeFillPlan) -> None:
        last_time_array = [long.MaxValue] * len(paths)
        series_paths = []

        for i in range(len(paths)):
            series_paths.append(paths[i])

        last_value_container = LastQueryExecutor.calculate_last_pair_for_series_locally(
            series_paths,
            data_types,
            context,
            None,
            plan.get_device_to_measurements()
        )

        for i, pair in enumerate(last_value_container):
            if pair.left:
                last_time_array[i] = pair.right.timestamp

    def has_next_without_constraint(self) -> bool:
        return self.group_by_engine_data_set.has_next_without_constraint()

    def next_without_constraint(self) -> RowRecord:
        row_record = self.group_by_engine_data_set.next_without_constraint()
        
        for i in range(len(paths)):
            field = row_record.get_fields()[i]
            
            if field is None or field.data_type is None:
                data_type = data_types[i]

                # For desc query peek previous time and value
                if not self.ascending and not self.is_peek_ended and not can_use_cache_data(row_record, data_type, i):
                    fill_cache(i)

                if can_use_cache_data(row_record, data_type, i):
                    row_record.get_fields()[i] = Field(field.data_type).get_field(previous_values[i])
                else:
                    previous_values[i] = field.object_value
                    previous_times[i] = row_record.timestamp

        return row_record

    def fill_cache(self, i: int) -> None:
        data = self.group_by_engine_data_set.peek_next_not_null_value(paths[i], i)

        if data is None:
            self.is_peek_ended = True
            previous_times[i] = long.MinValue
            previous_values[i] = None

        else:
            previous_values[i] = data.right
            previous_times[i] = data.left

    def can_use_cache_data(self, row_record: RowRecord, data_type: TSDataType, i: int) -> bool:
        return not cache_is_empty(i) and satisfy_time(row_record, data_type, self.fill_types[data_type], last_time_array[i]) and satisfy_range(data_type, self.fill_types[data_type])

    def is_increasing_time(self, row_record: RowRecord, time: long) -> bool:
        return row_record.timestamp >= time

    def satisfy_time(self, row_record: RowRecord, data_type: TSDataType, fill: PreviousFill, last_time: long) -> bool:
        if self.fill_types.get(data_type):
            return not fill.is_until_last() or row_record.timestamp <= last_time
        else:
            return True

    def satisfy_range(self, data_type: TSDataType, fill: PreviousFill) -> bool:
        return not self.fill_types.get(data_type) or fill.before_range < 0 or fill.before_range >= self.group_by_engine_data_set.interval

    def cache_is_empty(self, i: int) -> bool:
        return previous_values[i] is None

    def first_cache_is_empty(self, i: int) -> bool:
        return first_not_null_tvs[i] is None or first_not_null_tvs[i].value is None
```

Please note that the translation of Java code to Python may not be exact and might require some adjustments based on your specific use case.