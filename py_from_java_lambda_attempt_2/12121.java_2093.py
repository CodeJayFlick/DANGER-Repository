Here is the translation of the given Java code into Python:

```Python
class FieldMatchQuery:
    def __init__(self, column: int, value):
        self.column = column
        self.value = value

    def matches(self, record) -> bool:
        return record.field_equals(column, value)
```

Note that I've used type hints for the `column` and `value` parameters in the constructor to indicate their types.