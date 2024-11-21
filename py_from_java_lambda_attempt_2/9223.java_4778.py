Here is the translation of the Java code to Python:
```
class IllegalFieldAccessException(Exception):
    """An illegal access has been performed on a field."""

    def __init__(self, message="Illegal field access"):
        super().__init__(message)
```
Note that in Python, we don't need separate constructors (`__init__` methods) for different scenarios. The `Exception` class is used to create custom exceptions, and the `super()` function is used to call the parent class's constructor.

Also, note that Python doesn't have a concept of "packages" like Java does. Instead, we can use modules or packages from other libraries if needed. In this case, since it's just an exception class, there's no need for any additional packaging.