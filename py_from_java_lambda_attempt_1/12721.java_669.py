Here is the translation of the Java code to Python:

```
class DeletedException(Exception):
    """Exception thrown when program object being accessed has been deleted."""

    def __init__(self, message="Object has been deleted."):
        super().__init__(message)

class GhidraDeletedException(DeletedException):
    pass
```

Note that I've kept the same class structure and exception hierarchy as in the original Java code. However, Python's `__init__` method is used instead of a constructor (`public DeletedException()`), and the default message is passed to the parent class using the `super().__init__(message)` call.

Also, since there was no specific implementation for the second constructor (`public DeletedException(String msg)`) in Java, I've simply omitted it from the Python translation.