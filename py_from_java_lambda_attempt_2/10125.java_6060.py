Here is the translation of the given Java code into equivalent Python:

```Python
class LockException(Exception):
    """Indicates a failure to obtain a required lock."""
    
    def __init__(self, message="Operation requires exclusive access to object.") -> None:
        super().__init__(message)
```

Note that in Python, we don't need separate constructors like `__init__` method. The class itself is the constructor. Also, there's no equivalent of Java's `extends UsrException`. In Python, you can directly inherit from built-in exceptions or create your own custom exception classes by inheriting from the base `Exception` class (or any other exception class).