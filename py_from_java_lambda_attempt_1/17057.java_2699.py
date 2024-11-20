Here is the translation of the Java code to Python:
```
class LocalIoTDBConfiguration:
    def __init__(self, device: str, measurements: list[str], data_types: list[TSDataType]):
        self.device = PartialPath(device)
        self.measurements = measurements
        self.data_types = data_types

    @property
    def device(self):
        return self._device

    @property
    def measurements(self):
        return self._measurements

    @property
    def data_types(self):
        return self._data_types


class PartialPath:
    def __init__(self, path: str):
        self.path = path


TSDataType = enum('TSDataType', 'INT64', 'BOOLEAN', 'TEXT')
```
Note that I've used the `enum` class from Python's standard library to define an enumeration for `TSDataType`. This is equivalent to Java's `enums` in the original code.

Also, I've used Python's built-in list and string types instead of Java's array and String classes.