Here is the translation of the Java interface `IBatchDataIterator` to a Python class:
```python
class IBatchDataIterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self):
        raise NotImplementedError("Subclasses must implement this method")

    def current_time(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def current_value(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def reset(self):
        raise NotImplementedError("Subclasses must implement this method")

    def total_length(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
```
Note that I used the `NotImplementedError` exception to indicate that each of these methods is intended to be implemented by subclasses, rather than being implemented directly in this base class.