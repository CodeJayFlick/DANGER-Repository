Here is the translation of the Java code into Python:

```Python
class TestDoubleDataTypeManager:
    def __init__(self):
        self.id = UniversalIdGenerator.next_id()

    def get_universal_id(self):
        return self.id

    def contains_category(self, path):
        raise UnsupportedOperationException()

    def get_unique_name(self, path, base_name):
        raise UnsupportedOperationException()

    def resolve(self, data_type, handler):
        raise UnsupportedOperationException()

    def add_data_type(self, data_type, handler):
        raise UnsupportedOperationException()

    def add_data_types(self, data_types, handler, monitor):
        raise UnsupportedOperationException()

    def get_all_data_types(self):
        return []

    def get_all_structures(self):
        return []

    def find_data_types(self, name, list_):
        raise UnsupportedOperationException()

    def replace_data_type(self, existing_dt, replacement_dt, update_category_path=False):
        raise DataTypeDependencyException

    def get_data_type(self, data_type_path):
        raise UnsupportedOperationException()

    def find_data_type(self, data_type_path):
        return None

    def close(self):
        pass
```

Please note that this is a direct translation of the Java code into Python. It may not be perfect and might require some adjustments to work correctly in your specific use case.

Also, please note that `UniversalIdGenerator`, `CancelledException`, `TaskMonitor`, `DataTypeDependencyException` are all classes from the Ghidra framework which you will need to implement or import if they're available in Python.