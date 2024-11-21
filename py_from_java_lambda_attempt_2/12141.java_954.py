Here is the translation of the given Java code into equivalent Python:

```Python
class AddressFormatException(Exception):
    """An exception that gets raised when a string cannot be parsed as an address."""
    
    def __init__(self, message="Cannot parse string into address.") -> None:
        super().__init__(message)
```

Note: In Python, we don't need to explicitly define the constructor (`__init__`) method. The `Exception` class in Python is similar to the `UsrException` class in Java.