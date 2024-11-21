Here is the translation of the Java code to Python:
```
class NotFoundException(Exception):
    """Exception thrown when an object is not found."""

    def __init__(self, msg="Object was not found."):
        super().__init__(msg)
```
Note that I've kept the same class name and exception type as in the original Java code. In Python, we don't need to specify a package or import statements for this simple example.

The `__init__` method is equivalent to the constructor in Java. It takes an optional `msg` parameter with a default value of `"Object was not found."`. The `super().__init__(msg)` call invokes the parent class's (`Exception`) constructor, passing the message as an argument.