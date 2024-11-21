class TestDoubleCategory:
    def __init__(self, name):
        self.category_name = name

    def get_name(self):
        return self.category_name

    def compare_to(self, o):
        raise NotImplementedError("Not implemented")

    def set_name(self, name):
        if not isinstance(name, str):
            raise TypeError("Name must be a string")
        try:
            self.category_name = name
        except Exception as e:
            raise DuplicateNameException(f"Duplicate category: {name}") from e

    def get_categories(self):
        raise NotImplementedError("Not implemented")

    def get_data_types(self):
        raise NotImplementedError("Not implemented")

    def get_data_types_by_base_name(self, name):
        raise NotImplementedError("Not implemented")

    def add_data_type(self, dt, handler=None):
        if not isinstance(dt, dict) and not isinstance(dt, list):
            raise TypeError("Data type must be a dictionary or a list")
        raise NotImplementedError("Not implemented")

    def get_category(self, name):
        raise NotImplementedError("Not implemented")

    def get_category_path(self):
        raise NotImplementedError("Not implemented")

    def get_data_type(self, name):
        raise NotImplementedError("Not implemented")

    def create_category(self, name):
        if not isinstance(name, str):
            raise TypeError("Name must be a string")
        raise NotImplementedError("Not implemented")

    def remove_category(self, name, monitor=None):
        raise NotImplementedError("Not implemented")

    def remove_empty_category(self, name, monitor=None):
        raise NotImplementedError("Not implemented")

    def move_category(self, category, monitor=None):
        if not isinstance(category, TestDoubleCategory):
            raise TypeError("Category must be a TestDoubleCategory")
        raise NotImplementedError("Not implemented")

    def copy_category(self, category, handler=None, monitor=None):
        if not isinstance(category, TestDoubleCategory):
            raise TypeError("Category must be a TestDoubleCategory")
        raise NotImplementedError("Not implemented")

    def get_parent(self):
        raise NotImplementedError("Not implemented")

    def is_root(self):
        return False

    def get_category_path_name(self):
        raise NotImplementedError("Not implemented")

    def get_root(self):
        raise NotImplementedError("Not implemented")

    def get_data_type_manager(self):
        raise NotImplementedError("Not implemented")

    def move_data_type(self, type, handler=None):
        if not isinstance(type, dict) and not isinstance(type, list):
            raise TypeError("Data type must be a dictionary or a list")
        raise NotImplementedError("Not implemented")

    def remove(self, type, monitor=None):
        raise NotImplementedError("Not implemented")

    def get_id(self):
        return None
