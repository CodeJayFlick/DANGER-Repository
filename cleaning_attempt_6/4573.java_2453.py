class ColumnDisplayDynamicTableColumnAdapter:
    def __init__(self, display):
        self.display = display

    @property
    def column_name(self):
        return self.display.column_name()

    @property
    def column_class(self):
        return type(self.display.get_column_value(None))

    def get_value(self, row_object: 'AddressableRowObject', settings=None, program=None, service_provider=None) -> object:
        if not isinstance(row_object, AddressableRowObject):
            raise ValueError("Invalid row object")
        return self.display.get_column_value(row_object)

    def compare(self, o1: 'AddressableRowObject', o2: 'AddressableRowObject') -> int:
        return self.display.compare(o1, o2)
