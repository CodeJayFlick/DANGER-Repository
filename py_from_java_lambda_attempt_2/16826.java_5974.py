Here's the translation of the given Java interface into a Python equivalent:

```Python
class IReaderSet:
    def __init__(self):
        pass

    def set_reader(self, reader: 'TsFileSequenceReader'):
        pass

    def set_measurement_ids(self, measurement_ids: list) -> None:
        pass

    def set_read_device_id(self, is_read_device_id: bool) -> None:
        pass

    def set_read_time(self, is_read_time: bool) -> None:
        pass
```

Note that Python does not have an exact equivalent of Java's interface. Instead, we define a class `IReaderSet` with methods that are similar to the ones in the original Java code. The types and return values of these methods match those from the Java code as closely as possible.

Also note that I used type hints for the method parameters (e.g., `'TsFileSequenceReader'`) which is not strictly necessary but can be helpful when working with other Python developers or using tools like mypy to check your code's types.