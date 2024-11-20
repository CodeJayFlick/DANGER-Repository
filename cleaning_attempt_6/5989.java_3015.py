class ProgramMappedTableColumn(mapper_type: type, column_type: type):
    def __init__(self, mapper: 'TableRowMapper', table_column: 'DynamicTableColumn'):
        super().__init__(mapper, table_column)

    def __init__(self, mapper: 'TableRowMapper', table_column: 'DynamicTableColumn', unique_identifier: str):
        super().__init__(mapper, table_column, unique_identifier)
