Here is the equivalent Python code:

```Python
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
```

Note that Python does not have an exact equivalent to Java's enum. Instead, we define a class `ThreadTableColumns` with the same properties and methods as in the original code.

Also note that I used type hints for the function parameters and return types, which is optional but recommended in modern Python.