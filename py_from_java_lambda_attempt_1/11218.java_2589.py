Here is the translation of the Java code to Python:
```
class BusyToolException(Exception):
    """Exception thrown if an operation cannot be done because the tool has background tasks running."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
```
Note that I've kept the same class name and exception type as in the original Java code. In Python, we don't need to specify a package or import statements for this simple example.

The `__init__` method is equivalent to the constructor in Java, where we pass the message string to the parent Exception class using the `super()` function.