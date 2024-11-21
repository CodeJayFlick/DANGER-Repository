Here is the translation of the Java code to Python:
```
class ObjectiveC2_Cache:
    def __init__(self, state: 'ObjectiveC2_State', reader):
        self._state = state
        if state.is_32bit:
            self.cache = int.from_bytes(reader.read_next_int().to_bytes(4), byteorder='little')
        else:
            self.cache = long.from_bytes(reader.read_next_long().to_bytes(8), byteorder='little')

    @property
    def cache(self):
        return self._cache

    def to_data_type(self) -> 'DataType':
        if self._state.is_32bit:
            return {'name': 'Cache', 'type': int}
        else:
            return {'name': 'Cache', 'type': long}

    def apply_to(self):
        pass
```
Note that I've used Python's type hints to indicate the types of variables and function parameters, but these are not enforced at runtime. Also, I've replaced Java's `throws` clauses with Python's `->` notation for return types.

In particular:

* The `__init__` method is equivalent to the Java constructor.
* The `cache` property is equivalent to a getter/setter pair in Java.
* The `to_data_type` method returns a dictionary representing a data type, which is similar to how Java's `TypedefDataType` class works.
* The `apply_to` method does nothing, as it has no direct equivalent in Python.