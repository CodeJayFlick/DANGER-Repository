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
