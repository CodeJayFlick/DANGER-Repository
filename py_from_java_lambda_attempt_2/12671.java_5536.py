Here is the translation of the given Java code into Python:

```Python
class ScalarOverflowException(Exception):
    """A ScalarOverflowException indicates that some precision would be lost.
       If the operation was signed, unused bits did not match the sign bit.
       If the operation was unsigned, unsed bits were not all zero"""

    def __init__(self, message="Scalar overflow"):
        super().__init__(message)
```

Note: Python does not have a direct equivalent to Java's `extends` keyword. Instead, we use inheritance by making our class inherit from another class (in this case, the built-in `Exception` class).