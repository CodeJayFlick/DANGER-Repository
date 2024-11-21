Here is the translation of the Java interface `ShiftedReference` into a Python class:

```python
class ShiftedReference:
    def __init__(self):
        pass

    def get_shift(self) -> int:
        """Returns the left shift amount."""
        raise NotImplementedError("Subclasses must implement this method")

    def get_value(self) -> int:
        """Returns the base value."""
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define an abstract class using inheritance from another class (in this case, `object`). The methods are declared as abstract by raising the `NotImplementedError`.