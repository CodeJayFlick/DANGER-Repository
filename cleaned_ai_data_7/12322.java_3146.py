class Category:
    DELIMITER_CHAR = '/'
    NAME_DELIMITER = '/'
    DELIMITER_STRING = '/' + ''

    def __init__(self):
        pass

    @property
    def name(self):
        raise NotImplementedError("Subclasses must implement this method")

    @name.setter
    def set_name(self, value):
        if not isinstance(value, str):
            raise InvalidNameException()
        self._name = value

    def get_categories(self):
        return []

    def add_data_type(self, dt, handler=None):
        pass  # This is a placeholder for the actual implementation.

    @property
    def category_path(self):
        raise NotImplementedError("Subclasses must implement this method")

    def create_category(self, name) -> 'Category':
        if not isinstance(name, str):
            raise InvalidNameException()
        return Category()  # This is a placeholder for the actual implementation.

    def remove_category(self, name: str, monitor=None) -> bool:
        pass  # This is a placeholder for the actual implementation.

    @property
    def parent(self):
        raise NotImplementedError("Subclasses must implement this method")

    def move_category(self, category: 'Category', monitor=None):
        pass  # This is a placeholder for the actual implementation.

    def copy_category(self, category: 'Category', handler=None) -> 'Category':
        return Category()  # This is a placeholder for the actual implementation.

    @property
    def root(self):
        raise NotImplementedError("Subclasses must implement this method")

    @property
    def data_type_manager(self):
        raise NotImplementedError("Subclasses must implement this method")

    def move_data_type(self, type: 'DataType', handler=None) -> None:
        pass  # This is a placeholder for the actual implementation.

    def remove(self, type: 'DataType', monitor=None) -> bool:
        return False
