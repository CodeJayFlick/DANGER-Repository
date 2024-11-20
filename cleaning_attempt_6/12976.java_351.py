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
