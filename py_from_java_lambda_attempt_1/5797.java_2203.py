Here is the translation of the Java code to Python:
```
class ProgramConflictException(Exception):
    """Exception for incompatible programs when comparing programs for differences or when merging program differences."""

    def __init__(self, msg=""):
        super().__init__(msg)
```
Note that I've used the built-in `Exception` class in Python as a base class for our custom exception. The constructor (`__init__`) takes an optional message parameter, which is passed to the parent class's constructor using the `super()` function.

In Python, we don't need explicit constructors like Java does with its `public ProgramConflictException()` and `public ProgramConflictException(String msg)` methods. Instead, we define a single `__init__` method that initializes the exception object.