Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod

class AbstractGTableModel(metaclass=ABCMeta):
    WIDTH_UNDEFINED = -1
    
    def __init__(self):
        self.last_selected_objects = []

    @abstractmethod
    def get_row_object(self, row: int) -> object:
        pass

    @abstractmethod
    def get_index_of_row_object(self, row_object: object) -> int:
        pass

    @abstractmethod
    def get_model_data(self) -> list:
        pass

    def refresh(self):
        self.fire_table_data_changed()

    def get_last_selected_objects(self) -> list:
        return self.last_selected_objects

    def set_last_selected_objects(self, last_selected_objects: list):
        self.last_selected_objects = last_selected_objects

    def get_preferred_column_width(self, column_index: int) -> int:
        return AbstractGTableModel.WIDTH_UNDEFINED

    def value_at(self, row_index: int, column_index: int) -> object:
        model_data = self.get_model_data()

        if row_index < 0 or row_index >= len(model_data):
            return None
        
        t = model_data[row_index]
        return self.column_value_for_row(t, column_index)

    @abstractmethod
    def column_value_for_row(self, row_object: object, column_index: int) -> object:
        pass

    def index_of_row_object(self, row_object: object) -> int:
        return self.index_of_row_object(row_object, self.get_model_data())

    def index_of_row_object(self, row_object: object, data: list) -> int:
        try:
            return data.index(row_object)
        except ValueError:
            return -1

    def dispose(self):
        self.last_selected_objects.clear()
        self.get_model_data().clear()

class RowObjectTableModel(metaclass=ABCMeta):
    @abstractmethod
    def get_row_object(self, row: int) -> object:
        pass

class SelectionStorage(metaclass=ABCMeta):
    @abstractmethod
    def set_last_selected_objects(self, last_selected_objects: list):
        pass
```

Note that I've used Python's built-in `list` type instead of Java's `ArrayList`. Also, the abstract methods are marked with the `@abstractmethod` decorator.