class ColumnData:
    def __init__(self):
        pass

    def get_column_name(self) -> str:
        """Returns the name of the column being filtered."""
        raise NotImplementedError("Subclasses must implement this method")

    def count(self) -> int:
        """Returns the number of column values (unfiltered table row count)."""
        raise NotImplementedError("Subclasses must implement this method")

    def get_column_value(self, row: int) -> object:
        """Returns the column value for the given row."""
        raise NotImplementedError("Subclasses must implement this method")

    def get_table_data_source(self) -> object:
        """Returns the table's DataSource."""
        raise NotImplementedError("Subclasses must implement this method")
