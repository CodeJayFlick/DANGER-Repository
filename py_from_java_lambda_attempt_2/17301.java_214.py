Here is the translation of the given Java code into Python:

```Python
class QueryPlan:
    def __init__(self):
        self.result_columns = None
        self.paths = None
        self.data_types = None
        self.align_by_time = True  # for disable align sql
        self.row_limit = 0
        self.row_offset = 0
        self.ascending = True

        self.path_to_index = {}
        self.enable_redirect = False
        self.enable_tracing = False

        self.without_any_null = None
        self.without_all_null = None

    def deduplicate(self, physical_generator):
        pass  # abstract method in Java, not implemented here

    @property
    def paths(self):
        return self.paths

    @paths.setter
    def set_paths(self, value):
        self(paths) = value

    @property
    def data_types(self):
        return self.data_types

    @data_types.setter
    def set_data_types(self, value):
        self(data_types) = value

    @property
    def row_limit(self):
        return self.row_limit

    @row_limit.setter
    def set_row_limit(self, value):
        self(row_limit) = value

    @property
    def row_offset(self):
        return self.row_offset

    @row_offset.setter
    def set_row_offset(self, value):
        self(row_offset) = value

    def has_limit(self):
        return self.row_limit > 0

    def is_align_by_time(self):
        return self.align_by_time

    def set_align_by_time(self, align):
        self.align_by_time = align

    def set_column_name_to_dataset_output_index(self, column_name, index):
        self.path_to_index[column_name] = index

    @property
    def path_to_index(self):
        return self.path_to_index

    @path_to_index.setter
    def set_path_to_index(self, value):
        self(path_to_index) = value

    @property
    def is_ascending(self):
        return self.ascending

    @is_ascending.setter
    def set_ascending(self, ascending):
        self.ascending = ascending

    def get_column_for_reader_from_path(self, path, path_index):
        result_column = self.result_columns[path_index]
        if result_column.has_alias():
            return result_column.get_alias()
        else:
            return path.get_exact_full_path()

    def get_column_for_display(self, column_for_reader, path_index):
        return self.result_columns[path_index].get_result_column_name()

    @property
    def is_enable_redirect(self):
        return self.enable_redirect

    @is_enable_redirect.setter
    def set_enable_redirect(self, value):
        self(enable_redirect) = value

    @property
    def is_enable_tracing(self):
        return self.enable_tracing

    @is_enable_tracing.setter
    def set_enable_tracing(self, value):
        self(enable_tracing) = value

    @property
    def result_columns(self):
        return self.result_columns

    @result_columns.setter
    def set_result_columns(self, value):
        self(result_columns) = value

    @property
    def is_without_any_null(self):
        return self.without_any_null

    @is_without_any_null.setter
    def set_without_any_null(self, value):
        self(without_any_null) = value

    @property
    def is_without_all_null(self):
        return self.without_all_null

    @is_without_all_null.setter
    def set_without_all_null(self, value):
        self(without_all_null) = value