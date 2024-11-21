Here is the translation of the Java interface `DBFieldIterator` into a Python class:

```python
import io


class DBFieldIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def has_previous(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def previous(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def delete(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've used the `NotImplementedError` exception to indicate that these methods are abstract and should be implemented by subclasses. This is similar to how Java interfaces work, where you would typically throw an `AbstractMethodError` if a concrete class didn't provide an implementation for an interface's method.

Also note that Python doesn't have built-in support for checked exceptions like Java does with its `throws IOException`. Instead, we can use the `NotImplementedError` exception to indicate that these methods are not implemented.