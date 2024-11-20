Here is the translation of the given Java code into Python:

```Python
class PatternValue:
    def __init__(self):
        pass

    def get_min_value(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_max_value(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that Python does not have an exact equivalent to Java's abstract classes and methods. Instead, we use the `NotImplementedError` exception in Python to indicate that a subclass of `PatternValue` is required to provide its own implementation for these methods.