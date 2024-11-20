Here is the translation of the Java code to Python:

```
class DebugFilterInformation:
    def __init__(self, n_events: int, n_specific_exceptions: int, n_arbitrary_exceptions: int):
        self.n_events = n_events
        self.n_specific_exceptions = n_specific_exceptions
        self.n_arbitrary_exceptions = n_arbitrary_exceptions

    @property
    def number_events(self) -> int:
        return self.n_events

    @property
    def number_specific_exceptions(self) -> int:
        return self.n_specific_exceptions

    @property
    def number_arbitrary_exceptions(self) -> int:
        return self.n_arbitrary_exceptions
```

Note that I used Python's `@property` decorator to create read-only properties for the three attributes. This is equivalent to Java's getter methods, but with a more concise syntax in Python.