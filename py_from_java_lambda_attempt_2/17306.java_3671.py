Here is the translation of the given Java code into equivalent Python:

```Python
class UDTFPlan:
    def __init__(self, zone_id):
        self.zone_id = zone_id
        super().__init__()
        self.operator_type = "UDTF"

    def deduplicate(self, physical_generator):
        indexed_paths = []
        for i in range(len(result_columns)):
            for path in result_columns[i].collect_paths():
                indexed_paths.append((path, i))
        
        indexed_paths.sort(key=lambda x: x[0])
        
        column_for_reader_set = set()
        column_for_display_set = set()

        for indexed_path in indexed_paths:
            original_path = indexed_path[0]
            original_index = indexed_path[1]

            is_udf = not isinstance(result_columns[original_index].get_expression(), TimeSeriesOperand)

            column_for_reader = get_column_for_reader_from_path(original_path, original_index)
            if column_for_reader not in column_for_reader_set:
                add_deduplicated_paths(original_path)
                add_deduplicated_data_types(is_udf and IoTDB.meta_manager.get_series_type(original_path) or data_types[original_index])
                self.path_name_to_reader_index[column_for_reader] = len(self.path_name_to_reader_index)
                column_for_reader_set.add(column_for_reader)

            column_for_display = get_column_for_display(column_for_reader, original_index)
            if column_for_display not in column_for_display_set:
                dataset_output_index = len(get_path_to_index())
                set_column_name_to_dataset_output_index(column_for_display, dataset_output_index)
                self.dataset_output_index_to_result_column_index[dataset_output_index] = original_index
                column_for_display_set.add(column_for_display)

    def construct_udf_executors(self, result_columns):
        for result_column in result_columns:
            result_column.get_expression().construct_udf_executors(self.expression_name2_executor, self.zone_id)

    def finalize_udf_executors(self, query_id):
        try:
            for executor in self.expression_name2_executor.values():
                executor.before_destroy()
        finally:
            UDFClassLoaderManager.getInstance().finalize_udf_query(query_id)

    def get_result_column_by_dataset_output_index(self, dataset_output_index):
        return result_columns[self.dataset_output_index_to_result_column_index[dataset_output_index]]

    def get_executor_by_function_expression(self, function_expression):
        return self.expression_name2_executor.get(function_expression.get_expression_string())

    def get_reader_index(self, path_name):
        return self.path_name_to_reader_index[path_name]

    @property
    def expression_name2_executor(self):
        return self._expression_name2_executor

    @expression_name2_executor.setter
    def expression_name2_executor(self, value):
        self._expression_name2_executor = value

    @property
    def path_name_to_reader_index(self):
        return self._path_name_to_reader_index

    @path_name_to_reader_index.setter
    def path_name_to_reader_index(self, value):
        self._path_name_to_reader_index = value

    @property
    def dataset_output_index_to_result_column_index(self):
        return self._dataset_output_index_to_result_column_index

    @dataset_output_index_to_result_column_index.setter
    def dataset_output_index_to_result_column_index(self, value):
        self._dataset_output_index_to_result_column_index = value


# Assuming these are class variables in the original Java code.
result_columns = []
data_types = []
IoTDB = None
UDFClassLoaderManager = None

zone_id = ZoneId()
udtf_plan = UDTFPlan(zone_id)
```

Note that Python does not have direct equivalents for some of the Java constructs, such as `Map` and `Set`. Instead, you can use dictionaries (`{}`) or sets (`set()`), respectively.