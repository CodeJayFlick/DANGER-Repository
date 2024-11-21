Here is the translation of the Java code to Python:
```
class StringIsNotEmptyColumnConstraint:
    def get_name(self):
        return "Is Not Empty"

    def accepts(self, value: str, context) -> bool:
        return not self._is_blank(value)

    @staticmethod
    def _is_blank(s: str) -> bool:
        return s.strip() == ""

    def get_column_type(self) -> type:
        from typing import Type
        return Type(str)

    def get_editor(self, column_data_source):
        from .do_nothing_constraint_editor import DoNothingColumnConstraintEditor
        return DoNothingColumnConstraintEditor(self)

    def get_group(self) -> str:
        return "z string"

    def get_constraint_value_string(self) -> str:
        return ""

    def parse_constraint_value(self, constraint_value_string: str, data_source):
        return self

# Define the DoNothingColumnConstraintEditor class
class DoNothingColumnConstraintEditor:
    def __init__(self, column_constraint):
        self.column_constraint = column_constraint

    # ... (rest of the methods)
```
Note that I've used Python's type hints to indicate the types of variables and method return values. I've also assumed that you have a separate file `do_nothing_constraint_editor.py` containing the implementation of the `DoNothingColumnConstraintEditor` class.

Also, in Python, we don't need to explicitly define getters for properties like Java does with getter methods (e.g., `getName()`). Instead, we can simply access the property directly. For example, instead of calling `self.getName()`, you would call just `constraint.get_name()`.