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
