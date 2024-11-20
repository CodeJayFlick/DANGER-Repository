class IntegerEditorProvider:
    def __init__(self, converter):
        self.converter = converter

    def get_editor(self, column_constraint: 'ColumnConstraint', column_data_source: 'ColumnData') -> 'ColumnConstraintEditor':
        return IntegerConstraintEditor(column_constraint, self.converter)

    def parse_value(self, value: str, data_source: object) -> object:
        long_value = int(value)
        return self.converter.from_long(long_value)

    def to_string(self, value: object) -> str:
        return str(value)


class ColumnConstraint:
    pass


class ColumnData:
    pass


class IntegerConstraintEditor:
    def __init__(self, column_constraint: 'ColumnConstraint', converter):
        self.column_constraint = column_constraint
        self.converter = converter

# Usage example:

converter = LongConverter()  # implement this class to convert T to long and back
editor_provider = IntegerEditorProvider(converter)
column_constraint = ColumnConstraint()
column_data_source = ColumnData()

editor = editor_provider.get_editor(column_constraint, column_data_source)

value = "123"  # parse value from string
parsed_value = editor_provider.parse_value(value, None)  # returns an object of type T

string_representation = editor_provider.to_string(parsed_value)
