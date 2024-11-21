Here is the translation of the given Java code into Python:

```Python
class TraceChangeType:
    def __init__(self):
        pass

    def get_type(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")

    def get_sub_type(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
```

Note that in Python, we don't have a direct equivalent of Java's interface. Instead, we can define an abstract base class (ABC) using the `abc` module or use inheritance to create a common base class for all subclasses. In this case, I've used ABCs with abstract methods (`get_type()` and `get_sub_type()`) that must be implemented by any subclass of `TraceChangeType`.