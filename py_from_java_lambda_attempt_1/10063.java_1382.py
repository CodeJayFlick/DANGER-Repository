Here is the translation of the given Java code into equivalent Python:

```Python
class NotConnectedException(Exception):
    """Indicates that the server connection is down.
       When this exception is thrown, the current operation should be aborted.
       At the time this exception is thrown, the user has already been informed 
       of a server error condition."""
    
    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    def __init__(self, msg: str, cause: Exception) -> None:
        super().__init__(msg, cause)
```

Note that Python does not have an equivalent to Java's `IOException` class. Instead, we can extend the built-in `Exception` class and use it as a base for our custom exception.