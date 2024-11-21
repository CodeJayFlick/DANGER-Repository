Here is the translation of the Java code to Python:
```
class UnsignedLongRangeEditorProvider:
    def get_editor(self, column_constraint: 'ColumnConstraint[int]', column_data: 'ColumnData[int]') -> 'ColumnConstraintEditor[int]':
        return UnsignedLongRangeConstraintEditor(column_constraint)

    def parse_value(self, value: str, data_source: object) -> int:
        return int(value, 16)

    def to_string(self, value: int) -> str:
        return hex(value)[2:]

class ColumnData:
    pass

class ColumnConstraint:
    pass

class UnsignedLongRangeConstraintEditor:
    def __init__(self, column_constraint):
        self.column_constraint = column_constraint
```
Note that I've used type hints to indicate the expected types of variables and function parameters. This is not strictly necessary in Python, but it can help with code readability and static analysis.

I've also replaced some Java-specific constructs, such as `@Override` annotations, with equivalent Python syntax (e.g., using a simple colon instead of an annotation).

The rest of the translation was straightforward: I simply converted each Java statement to its equivalent Python form.