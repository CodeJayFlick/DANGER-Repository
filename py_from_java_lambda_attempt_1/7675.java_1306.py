Here is the translation of the given Java code into equivalent Python:

```Python
class DemanglerParseException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
```

This Python class `DemanglerParseException` inherits from built-in exception class `Exception`. The constructor (`__init__`) takes a string argument and passes it to the parent's constructor using `super().__init__(message)`.

Note that there is no direct equivalent of Java's `public`, `extends RuntimeException`, or `throws` in Python.