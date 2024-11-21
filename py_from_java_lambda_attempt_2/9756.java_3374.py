Here is the translation of the Java interface `EditorProvider` to a Python class:

```python
class EditorProvider:
    def get_editor(self, column_constraint: 'ColumnConstraint', column_data: 'ColumnData') -> 'ColumnConstraintEditor':
        # implement your logic here
        pass

    def parse_value(self, value: str, data_source: object) -> any:
        # implement your logic here
        pass

    def to_string(self, value: any) -> str:
        # implement your logic here
        pass
```

Note that in Python:

* We don't have a direct equivalent of Java interfaces. Instead, we can use abstract base classes (ABCs) or regular classes with abstract methods.
* The `get_editor` method is implemented as an instance method (`def get_editor(self, ...)`) instead of a static method (`public static ColumnConstraintEditor<T> getEditor(...)`)
* We don't have generics in Python like Java does. Instead, we can use type hints to indicate the expected types of variables and function parameters.
* The `ColumnData` class is not defined here as it's an external dependency that needs to be imported or implemented separately.

This translation maintains the same structure and method signatures as the original Java interface, but uses Python syntax and features.