Here is the equivalent Python code:

```Python
class ObjectAttributeColumn:
    def __init__(self, header: str, cls: type, getter):
        self.header = header
        self.cls = cls
        self.getter = getter

    @property
    def header(self) -> str:
        return self._header

    @property
    def value_class(self) -> type:
        return self._cls

    def get_value_of(self, row):
        return self.getter(row)

# Define the columns as instances of ObjectAttributeColumn
NAME = ObjectAttributeColumn("Name", str, lambda row: row.name)
KIND = ObjectAttributeColumn("Kind", str, lambda row: row.kind)
VALUE = ObjectAttributeColumn("Value", str, lambda row: row.value)
TYPE = ObjectAttributeColumn("Type", str, lambda row: row.type)

# You can use these columns like this:
print(NAME.header)  # prints "Name"
print(VALUE.get_value_of(some_row))  # applies the getter function to some_row
```

Note that Python does not have direct equivalents of Java's enum or interface. Instead, we define a class `ObjectAttributeColumn` and create instances for each column. The `__init__`, `header`, `value_class`, and `get_value_of` methods are equivalent to the constructors, getter method, and overridden methods in the original code.