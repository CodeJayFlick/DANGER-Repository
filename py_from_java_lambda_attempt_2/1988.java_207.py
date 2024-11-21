Here is the translation of the given Java code into equivalent Python:

```Python
class GadpIllegalStateException(Exception):
    def __init__(self, message):
        super().__init__(message)

    def __init__(self, message, cause):
        super().__init__(message)
        self.__cause__ = cause

# Example usage:
try:
    # Some code that might raise an exception
except GadpIllegalStateException as e:
    print(f"Caught {e}")
```

Note: Python does not have a direct equivalent to Java's `extends` keyword. Instead, we define the class directly and use inheritance by calling the parent class (`Exception`) in the constructor using `super().__init__(message)`.