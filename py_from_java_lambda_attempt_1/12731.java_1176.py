Here is the translation of the Java code to Python:
```
class TypeMismatchException(Exception):
    def __init__(self, message="Type is not supported."):
        super().__init__(message)
```
Note that in Python:

* We don't need a `package` declaration or an explicit class definition.
* The exception class inherits from the built-in `Exception` class instead of `RuntimeException`.
* The constructors (`__init__`) are defined with keyword arguments, and we use the `super()` function to call the parent constructor.