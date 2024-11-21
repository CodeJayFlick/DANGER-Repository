Here is the translation of the Java code to Python:
```
class StringIsEmptyColumnConstraint:
    def get_name(self):
        return "Is Empty"

    def accepts(self, value: str, context) -> bool:
        from apache.commons.lang3 import StringUtils
        return StringUtils.isBlank(value)

    @property
    def column_type(self) -> type:
        return str

    def get_editor(self, column_data_source: 'ColumnData[str]') -> 'DoNothingColumnConstraintEditor[str]':
        from .constrainteditor import DoNothingColumnConstraintEditor
        return DoNothingColumnConstraintEditor(self)

    def get_group(self) -> str:
        return "string"

    def get_constraint_value_string(self) -> str:
        return ""

    def parse_constraint_value(self, constraint_value_string: str, data_source: object) -> 'StringIsEmptyColumnConstraint':
        return self
```
Note that I used the `from` statement to import modules and classes from other files or packages. In this case, I assumed that you have a file called `constrainteditor.py` in the same directory as this code, which contains the definition of the `DoNothingColumnConstraintEditor` class.

Also, I used type hints for function parameters and return types, but Python 3.x does not require these to be present. If you're using an older version of Python or prefer a more concise syntax, you can remove the type hints altogether.