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
