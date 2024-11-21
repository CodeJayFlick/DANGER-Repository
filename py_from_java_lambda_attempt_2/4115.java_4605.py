Here is the translation of the given Java code into equivalent Python:

```Python
class OsgiException(Exception):
    """Wrapper for exceptions originating with an OSGi operation."""
    
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        else:
            super().__init__(message)

# Example usage
try:
    # Your code here that might raise an exception
except OsgiException as e:
    print(f"OSGiException: {e}")
```

Note that Python does not have a direct equivalent to Java's `UsrException` class. Instead, we can use the built-in `Exception` class and create our own custom exception type (`OsgiException`) by subclassing it.