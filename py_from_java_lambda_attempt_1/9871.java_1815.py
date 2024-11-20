Here is the translation of the Java code to Python:
```
class ThreadedTableColumnComparator:
    def __init__(self, model: 'ThreadedTableModel', sort_column: int):
        self.model = model
        super().__init__(model, sort_column)

    @property
    def threaded_model(self) -> 'ThreadedTableModel':
        return self.model

    def get_column_value(self, t: object) -> object:
        return self.threaded_model.get_cached_column_value_for_row(t, self.sort_column)
```
Note that I've used Python's type hinting system to indicate the types of variables and method parameters. This is not strictly necessary for a working translation, but it can be helpful for documentation and static analysis purposes.

Also note that I've removed some Java-specific features like constructors with multiple parameters (Python uses keyword arguments instead), `@Override` annotations (not needed in Python), and the use of `<T>` to indicate type variables.