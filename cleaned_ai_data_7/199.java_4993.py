class ThreadTableColumns:
    def __init__(self, header: str, cls: type, getter: callable, setter: callable = None, sortable: bool = True):
        self.header = header
        self.cls = cls
        self.getter = getter
        if setter is not None:
            self.setter = lambda row, value: setter(row, value)
        else:
            self.setter = None
        self.sortable = sortable

    def get_header(self) -> str:
        return self.header

    def get_value_class(self) -> type:
        return self.cls

    def get_value_of(self, row):
        return self.getter(row)

    def is_editable(self, row):
        return self.setter is not None

    def is_sortable(self):
        return self.sortable

    def set_value_of(self, row, value):
        if self.setter:
            self.setter(row, value)
