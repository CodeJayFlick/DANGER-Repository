Here is the translation of the Java interface `BidiMap` to a Python class:

```python
class BidiMap:
    def __init__(self):
        pass  # No equivalent in Python; we'll define methods instead

    def get_reverse_view(self) -> 'BidiMap':
        raise NotImplementedError("Subclasses must implement this method")

    def get_key(self, value: object) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def get_value(self, key: object) -> object:
        raise NotImplementedError("Subclasses must implement this method")

    def values_set(self) -> set:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define an abstract base class (ABC) using the `abc` module or by raising `NotImplementedError`. In this case, I chose the latter.

Also, since Python is dynamically typed and doesn't require explicit type declarations like Java does, I omitted those parts of the code.