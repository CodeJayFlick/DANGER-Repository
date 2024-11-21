Here is the translation of the Java interface `DBLongIterator` into a Python class:

```python
import io

class DBLongIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def has_previous(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def previous(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def delete(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I did not include any specific implementation for the methods, as they are intended to be implemented by subclasses. The `NotImplementedError` is raised in each method to indicate that it should be overridden in a subclass.

Also, since Python does not have built-in support for checked exceptions like Java's `IOException`, I used the standard way of indicating an exception with a `raise` statement instead.