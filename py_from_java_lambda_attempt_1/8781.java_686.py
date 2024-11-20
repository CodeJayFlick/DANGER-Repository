Here is the translation of the Java code to Python:
```python
class TableDescriptor:
    def __init__(self):
        self.columns = self.discover_table_columns()

    def discover_table_columns(self):
        clazz = type(self)
        fields = list(clazz.__dict__.values())
        columns = []
        for field in fields:
            if isinstance(field, TableColumn):
                column = field
                column.name = str(field).split('.')[-1]
                column.ordinal = len(columns)
                columns.append(column)

    def get_indexed_columns(self):
        indexed_columns = [column.column() for column in self.columns if column.is_indexed()]
        return list(indexed_columns)

    def get_column_names(self):
        return [str(column) for column in self.columns]

    def get_column_fields(self):
        fields = []
        for i, column in enumerate(self.columns):
            field = column.get_column_field().new_field()
            fields.append(field)
        return fields


class TableColumn:
    pass
```
Note that I did not implement the `TableColumn` class as it was not provided. You will need to define this class separately.

Also, some Java-specific concepts like reflection and exception handling were replaced with Pythonic equivalents (e.g., using `type()` instead of `getClass()`, etc.).