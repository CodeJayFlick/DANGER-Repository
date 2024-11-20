Here is the translation of the Java interface `RecordIterator` into a Python class:

```python
import io


class RecordIterator:
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

Note that I've used the `NotImplementedError` exception to indicate that these methods are abstract and should be implemented by subclasses.