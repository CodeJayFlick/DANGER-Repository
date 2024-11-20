Here is the translation of the Java code to Python:
```
class ProgramMappedTableColumn(mapper_type: type, column_type: type):
    def __init__(self, mapper: 'TableRowMapper', table_column: 'DynamicTableColumn'):
        super().__init__(mapper, table_column)

    def __init__(self, mapper: 'TableRowMapper', table_column: 'DynamicTableColumn', unique_identifier: str):
        super().__init__(mapper, table_column, unique_identifier)
```
Note that I've used type hints to indicate the types of the `mapper_type` and `column_type` parameters. In Python, you don't need to specify explicit constructors like Java does with its `public class ProgramMappedTableColumn<...>` syntax.

Also, I've used single quotes `'` around the parameter names in the method signatures, which is a common convention in Python for indicating that they are intended as type hints rather than actual variable names.