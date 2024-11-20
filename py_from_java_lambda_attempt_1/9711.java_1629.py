Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractDynamicTableColumnStub:
    def __init__(self):
        pass

    @staticmethod
    def get_value(row_object: object, settings: dict, service_provider: object) -> any:
        raise NotImplementedError("Subclasses must implement this method")

    def getValue(self, rowObject: object, settings: dict, data: object,
                 serviceProvider: object) -> any:
        return self.get_value(rowObject, settings, serviceProvider)
```

Note that Python does not have direct equivalent of Java's generics. The `ROW_TYPE` and `COLUMN_TYPE` in the original code are replaced with `object`, which is a built-in type in Python representing an instance of some class.

The `AbstractDynamicTableColumnStub` class has been converted into a regular Python class, without any inheritance from other classes or interfaces.