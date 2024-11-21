Here is the translation of the Java code to Python:
```
class Preview:
    def __init__(self):
        pass

    def get_name(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_preview(self, memory: bytes, addr: int) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_data_type(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that I've used the `NotImplementedError` exception to indicate that these methods are abstract and should be implemented by subclasses. This is equivalent to the Java interface's requirement for implementing classes.

Also, in Python, we don't need an explicit `Comparable` interface like in Java, as all objects can be compared using built-in operators (`==`, `<`, etc.).