Here is the translation of the Java code to Python:
```
class NessieReferenceAlreadyExistsException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        elif message is not None:
            super().__init__(message)

    @property
    def error_code(self) -> int:
        return 1  # Assuming ErrorCode.REFERENCE_ALREADY_EXISTS == 1

class NessieError(Exception):
    pass
```
Note that I've used Python's built-in `Exception` class as the base class for both exceptions, and implemented the constructors using keyword arguments to allow for optional message and cause parameters.

I also replaced the Java-style enum constant (`ErrorCode.REFERENCE_ALREADY_EXISTS`) with a simple integer value (1) in this translation, since Python doesn't have an equivalent concept to enums. If you need more complex error codes or additional functionality, you may want to consider using a separate class or module for handling errors and exceptions in your Python code.