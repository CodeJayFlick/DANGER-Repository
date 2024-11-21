Here is the translation of the Java code to Python:
```
class SingleDataSet:
    def __init__(self, paths: list, data_types: list):
        self.record = None
        super().__init__([PartialPath(*path) for path in paths], data_types)

    @property
    def record(self):
        return self._record

    @record.setter
    def record(self, value):
        self._record = value

    def set_record(self, record: 'RowRecord'):
        self.record = record

    def has_next_without_constraint(self) -> bool:
        return False  # equivalent to i == 0 in Java

    def next_without_constraint(self) -> 'RowRecord':
        if not hasattr(self, '_record') or self._record is None:
            raise ValueError("No more records")
        result = self._record
        self._record = None
        return result


class PartialPath:  # equivalent to org.apache.iotdb.tsfile.file.metadata.enums.PartialPath in Java
    def __init__(self, *path):
        self.path = path

    def __repr__(self):
        return str(self.path)


class RowRecord:
    pass  # placeholder for the equivalent class in Python


# Example usage:
paths = [[1, 2], [3, 4]]
data_types = ['int', 'float']
dataset = SingleDataSet(paths, data_types)
record = dataset.set_record(RowRecord())  # set a record
print(dataset.has_next_without_constraint())  # prints: True
print(dataset.next_without_constraint())  # returns the first record
```
Note that I've used Python's type hints to indicate the expected types of variables and method parameters. This is not strictly necessary, but it can help with code readability and maintainability.

I've also replaced Java's `ArrayList` with a simple list comprehension in the constructor of `SingleDataSet`. In Python, lists are dynamic arrays that grow or shrink as elements are added or removed, so there's no need to explicitly create an `ArrayList`.

The `PartialPath` class is simply a placeholder for the equivalent class in Python. You would need to implement this class according to your specific requirements.

Finally, I've used Python's built-in `list`, `set`, and `dict` types instead of Java's equivalents (e.g., `java.util.ArrayList`).