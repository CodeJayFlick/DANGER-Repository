Here is the translation of the Java code into Python:

```Python
class AlignByDeviceDataSet:
    def __init__(self, align_by_device_plan: 'AlignByDevicePlan', query_context: 'QueryContext', query_router: 'IQueryRouter'):
        self.data_set_type = None
        self.query_router = query_router
        self.context = query_context

        self.measurements = align_by_device_plan.get_measurements()
        self.devices = align_by_device_plan.get_devices()
        self.measurement_info_map = align_by_device_plan.get_measurement_info_map()

        if align_by_device_plan.get_operator_type() == 'GROUP_BY_TIME':
            self.data_set_type = 'GROUP_BY_TIME'
            self.group_by_time_plan = align_by_device_plan.get_group_by_time_plan()
            self.group_by_time_plan.set_ascending(align_by_device_plan.is_ascending())
        elif align_by_device_plan.get_operator_type() == 'AGGREGATION':
            self.data_set_type = 'AGGREGATE'
            self.aggregation_plan = align_by_device_plan.get_aggregation_plan()
            self.aggregation_plan.set_ascending(align_by_device_plan.is_ascending())
        elif align_by_device_plan.get_operator_type() == 'FILL':
            self.data_set_type = 'FILL'
            self.fill_query_plan = align_by_device_plan.get_fill_query_plan()
            self.fill_query_plan.set_ascending(align_by_device_plan.is_ascending())

    def get_paths_num(self):
        return 0

    def has_next_without_constraint(self) -> bool:
        if not self.cur_data_set_initialized and self.current_data_set.has_next():
            return True
        else:
            self.cur_data_set_initialized = False

        while self.device_iterator.hasNext():
            current_device = next(self.device_iterator)
            measurement_of_given_device = get_measurements_under_given_device(current_device)

            execute_columns = []
            execute_paths = []
            ts_data_types = []
            execute_aggregations = []

            for entry in self.measurement_info_map.items():
                if entry[1].get_measurement_type() != 'Exist':
                    continue
                column, measurement_info = entry

                if self.data_set_type == 'GROUP_BY_TIME' or self.data_set_type == 'AGGREGATE':
                    execute_aggregations.append(column[:column.index('(')].strip())
                else:
                    execute_columns.append(column)
                    execute_paths.append(transform_path(current_device, column))
                    ts_data_types.append(measurement_info.get_measurement_data_type())

            if device_to_filter_map is not None:
                self.expression = device_to_filter_map.get(current_device.full_path)

            try:
                if self.data_set_type == 'GROUP_BY_TIME':
                    current_data_set = query_router.group_by(group_by_time_plan, context)
                elif self.data_set_type == 'AGGREGATE':
                    current_data_set = query_router.aggregate(aggregation_plan, context)
                elif self.data_set_type == 'FILL':
                    current_data_set = query_router.fill(fill_query_plan, context)

            except (QueryProcessException, QueryFilterOptimizationException, StorageEngineException) as e:
                raise IOException(e)

        if not current_data_set.has_next():
            return False

        self.cur_data_set_initialized = True
        return True

    def get_measurements_under_given_device(self, device: 'PartialPath') -> set:
        try:
            measurement_schemas = IoTDB.meta_manager.get_all_measurement_by_device_path(device)
            res = set()

            for schema in measurement_schemas:
                if isinstance(schema, VectorMeasurementSchema):
                    for sub_measurement in schema.get_sub_measurements_list():
                        res.add(f"{schema.measurement_id}.{sub_measurement}")
                else:
                    res.add(schema.measurement_id)

        except MetadataException as e:
            raise IOException("Cannot get node from " + device, e)
        return res

    def transform_path(self, device: 'PartialPath', measurement: str) -> 'PartialPath':
        try:
            full_path = PartialPath(device.full_path, measurement)
            schema = IoTDB.meta_manager.get_series_schema(full_path)

            if isinstance(schema, UnaryMeasurementSchema):
                return full_path
            else:
                vector_path = full_path.device
                return VectorPartialPath(vector_path, full_path.measurement)

        except MetadataException as e:
            raise IOException("Cannot get node from " + device, e)
        return None

    def next_without_constraint(self) -> 'RowRecord':
        origin_row_record = current_data_set.next()

        row_record = RowRecord(origin_row_record.timestamp)

        device_field = Field(TSDataType.TEXT)
        device_field.set_binary_v(Binary(current_device.full_path))
        row_record.add_field(device_field)

        measurement_fields = origin_row_record.get_fields()
        current_column_map = {}

        for i in range(len(measurement_fields)):
            current_column_map[execute_columns[i]] = measurement_fields[i]

        for measurement in self.measurements:
            if measurement_info_map[measurement].get_measurement_type() == 'Exist':
                row_record.add_field(current_column_map.get(measurement, None))
            elif measurement_info_map[measurement].get_measurement_type() == 'NonExist':
                row_record.add_field(Field(None))

        return row_record

class RowRecord:
    def __init__(self, timestamp):
        self.timestamp = timestamp
        self.fields = []

    def add_field(self, field: Field):
        self.fields.append(field)

    @property
    def get_fields(self) -> list:
        return self.fields


# Usage example:

align_by_device_plan = AlignByDevicePlan()
query_context = QueryContext()
query_router = IQueryRouter()

data_set = AlignByDeviceDataSet(align_by_device_plan, query_context, query_router)
has_next_without_constraint = data_set.has_next_without_constraint()  # Returns True or False
row_record = data_set.next_without_constraint()  # Returns a RowRecord object

```

Note that this translation is not exact and some parts may be missing. The original code has many Java-specific constructs (like `enum`, `try-catch` blocks, etc.) which are difficult to translate directly into Python.