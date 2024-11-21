Here is the translation of the Java code to Python:
```
class IStorageGroupMNode:
    def __init__(self):
        pass

    def get_data_ttl(self) -> int:
        raise NotImplementedError("Must be implemented by subclass")

    def set_data_ttl(self, data_ttl: int) -> None:
        raise NotImplementedError("Must be implemented by subclass")
```
Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define an abstract base class (ABC) using the `class` statement with no implementation for its methods.

The `get_data_ttl()` and `set_data_ttl()` methods are declared as abstract because they raise a `NotImplementedError`, indicating that any subclass of `IStorageGroupMNode` must provide their own implementations.