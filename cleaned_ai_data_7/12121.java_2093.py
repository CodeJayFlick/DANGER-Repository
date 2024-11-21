class FieldMatchQuery:
    def __init__(self, column: int, value):
        self.column = column
        self.value = value

    def matches(self, record) -> bool:
        return record.field_equals(column, value)
