from abc import ABCMeta, abstractmethod
import collections

class ObjectEnumeratedColumnTableModel(metaclass=ABCMeta):
    def __init__(self, name: str, cols) -> None:
        self.name = name
        self.cols = cols
        self.model_data = []

    @abstractmethod
    def get_value_of(self, row: object) -> object:
        pass

    class ObjectsEnumeratedTableColumn(metaclass=ABCMeta):
        @abstractmethod
        def get_value_of(self, row: object) -> object:
            pass

        @abstractmethod
        def get_header(self) -> str:
            pass

        @abstractmethod
        def set_value_of(self, row: object, value: object) -> None:
            pass

    class TableRowIterator:
        def __init__(self, model_data):
            self.it = iter(model_data)
            self.index = 0

        def has_next(self) -> bool:
            return next((True for _ in range(1)), False)

        def next(self) -> object:
            self.index += 1
            return next(self.it)

        def has_previous(self) -> bool:
            if not hasattr(self, 'it'):
                raise ValueError("Iterator is exhausted")
            return True

        def previous(self) -> object:
            self.index -= 1
            return next(reversed(list(self.it)))

        def remove(self):
            try:
                del list(self.it)[self.index - 1]
            except (ValueError, IndexError):
                pass
            self.fire_table_rows_deleted(self.index - 1, self.index)

        def set(self, e: object) -> None:
            try:
                list(self.it).insert(self.index - 1, e)
            except ValueError as ve:
                raise ve

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        self._name = value

    @property
    def model_data(self) -> list:
        return self._model_data

    @model_data.setter
    def model_data(self, value: list):
        if not all(isinstance(x, object) for x in value):
            raise TypeError("Model data must be a list of objects")
        self._model_data = value

    def set_columns(self, cols: list):
        self.cols = cols
        self.fire_table_structure_changed()

    @property
    def columns(self) -> list:
        return self._cols

    @columns.setter
    def columns(self, value: list):
        if not all(isinstance(x, ObjectEnumeratedColumnTableModel.ObjectsEnumeratedTableColumn) for x in value):
            raise TypeError("Columns must be a list of ObjectsEnumeratedTableColumn")
        self._cols = value

    def fire_table_structure_changed(self):
        pass  # TO DO

    @property
    def default_sort_order(self) -> list:
        return []

    def get_row_count(self) -> int:
        return len(self.model_data)

    def get_column_count(self) -> int:
        return len(self.cols)

    def get_value_at(self, row_index: int, column_index: int) -> object:
        if 0 <= row_index < self.get_row_count():
            return self.cols[column_index].get_value_of(self.model_data[row_index])
        else:
            return ""

    def set_value_at(self, value: object, row_index: int, column_index: int):
        if not isinstance(value, str) and not issubclass(type(value), (int, float)):
            raise TypeError("Value must be a string or an integer/float")
        self.cols[column_index].set_value_of(self.model_data[row_index], value)
        self.fire_table_cell_updated(row_index, column_index)

    def fire_table_cell_updated(self, row: int, column: int):
        pass  # TO DO

    @property
    def is_cell_editable(self) -> bool:
        return False

    def add(self, e: object):
        if not isinstance(e, object):
            raise TypeError("Element must be an object")
        self.model_data.append(e)
        self.fire_table_rows_inserted(len(self.model_data), len(self.model_data))

    @property
    def notify_updated(self) -> bool:
        return False

    def fire_table_rows_inserted(self, first_row: int, last_row: int):
        pass  # TO DO

    def add_all(self, c: list):
        if not all(isinstance(x, object) for x in c):
            raise TypeError("Collection must be a list of objects")
        self.model_data.extend(c)
        self.fire_table_rows_inserted(len(self.model_data), len(self.model_data))

    @property
    def notify_updated_with_predicate(self) -> bool:
        return False

    # TO DO: implement this method
    def find_first(self, predicate):
        for row in self.model_data:
            if predicate(row):
                return row
        return None

    def clear(self):
        self.model_data.clear()
        self.fire_table_data_changed()

    @property
    def notify_updated_with_predicate_and_row_index(self) -> bool:
        return False

    # TO DO: implement this method
    def delete(self, e: object):
        if not isinstance(e, object):
            raise TypeError("Element must be an object")
        self.model_data.remove(e)
        self.fire_table_rows_deleted(len(self.model_data), len(self.model_data))

    @property
    def notify_updated_with_predicate_and_row_index2(self) -> bool:
        return False

    # TO DO: implement this method
    def get_row(self, index):
        if 0 <= index < self.get_row_count():
            return self.model_data[index]
        else:
            raise IndexError("Row index out of range")

    @property
    def notify_updated_with_predicate_and_row_index3(self) -> bool:
        return False

    # TO DO: implement this method
    def update_columns(self, x):
        if not isinstance(x, object):
            raise TypeError("Object must be an object")
        keys = [str(key) for key in x.get_keys()]
        self.cols = ObjectEnumeratedColumnTableModel.ObjectsEnumeratedTableColumn.generate_columns(keys)

    @property
    def notify_updated_with_predicate_and_row_index4(self) -> bool:
        return False

    # TO DO: implement this method
    def fire_table_changed(self, e):
        if SwingUtilities.is_event_dispatch_thread():
            super().fire_table_changed(e)
            return
        final_e = e
        SwingUtilities.invokeLater(lambda: super().fire_table_changed(final_e))
