Here is the translation of the Java code to Python:
```
class ThreadedBackupRowComparator:
    def __init__(self, threaded_model: 'ThreadedTableModel', sort_column: int):
        super().__init__(threaded_model, sort_column)
        self.threaded_model = threaded_model

    def get_column_value(self, t) -> object:
        return self.threaded_model.get_cached_column_value_for_row(t, self.sort_column)

class ThreadedTableModel:
    pass  # This class is not defined in the original Java code
```
Note that I did not translate the `ThreadedTableModel` class as it was not provided in the original Java code. Also, Python does not have a direct equivalent to Java's generics system, so I omitted the type parameter `<T>` and `<?>`.