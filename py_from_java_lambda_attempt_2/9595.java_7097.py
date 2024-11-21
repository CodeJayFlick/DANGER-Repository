Here is the translation of the Java code to Python:
```
class DefaultRowColLocation:
    def __init__(self):
        self.row = 0
        self.col = 0

    def __init__(self, row: int, col: int):
        self.row = row
        self.col = col

    def with_col(self, new_column: int) -> 'DefaultRowColLocation':
        return DefaultRowColLocation(new_column, self.row)

    def with_row(self, new_row: int) -> 'DefaultRowColLocation':
        return DefaultRowColLocation(new_row, self.col)
```
Note that I've used Python's `__init__` method to initialize the object, and the `with_col` and `with_row` methods are implemented as simple constructors. The type hints (`-> 'DefaultRowColLocation'`) are not strictly necessary in Python 3.x, but they can help with code readability and static analysis tools like mypy.