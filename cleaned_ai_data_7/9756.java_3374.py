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
