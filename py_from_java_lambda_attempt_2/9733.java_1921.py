Here is the translation of the Java interface `ColumnData` to a Python class:

```python
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
```

Note that I've used Python's type hints to indicate the expected types of the methods' return values. In particular, `get_column_value` is expected to return an instance of some generic type `T`, which has been replaced with `object` in the translation since Python does not support generics.

Also note that this class definition uses a similar structure and naming conventions as the original Java interface, but it's not possible to directly translate interfaces into classes without additional information.