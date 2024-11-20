Here is the translation of the given Java code into Python:

```Python
class FieldRangeQuery:
    def __init__(self, column: int, min_value: 'Field', max_value: 'Field'):
        self.column = column
        self.min = min_value
        self.max = max_value

    def matches(self, record: 'DBRecord') -> bool:
        return (record.compare_field_to(self.column, self.min) > 0) and (record.compare_field_to(self.column, self.max) < 0)


class DBRecord:
    pass


class Field:
    pass
```

Please note that the `Field` and `DBRecord` classes are not implemented in this translation. They were likely defined elsewhere in the original Java code or have their own definitions.