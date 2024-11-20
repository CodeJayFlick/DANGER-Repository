Here is the translation of the Java code into Python:

```Python
class CircularDependencyException(Exception):
    def __init__(self, message="Reference is invalid."):
        super().__init__(message)
```

Note that in Python, we don't need to specify a separate class for exceptions like `UsrException` because all built-in exceptions are subclasses of the base exception class (`Exception`).