Here is the translation of the given Java code into Python:

```Python
class Iterator:
    def __init__(self):
        pass

    def has_next(self) -> bool:
        raise NotImplementedError("Subclasses must implement this method")

    def next(self) -> object:
        raise NotImplementedError("Subclasses must implement this method")
```

This is a simple translation of the Java interface into Python. The `__init__` method in Python does not have an equivalent to the constructor in Java, but it's often used for initialization purposes.