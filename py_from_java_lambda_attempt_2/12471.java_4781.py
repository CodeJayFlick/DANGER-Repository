Here is the translation of the given Java code into Python:

```Python
class InsufficientBytesException(Exception):
    """An exception indicating that there were not enough consecutive bytes available to fully parse an instruction."""
    
    def __init__(self, message="Not enough bytes available to parse a legal instruction"):
        super().__init__(message)
```

Note: In the given Java code, `UsrException` is extended in Python with built-in exception class.