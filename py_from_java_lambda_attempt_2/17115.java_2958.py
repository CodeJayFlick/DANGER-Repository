Here is the translation of the Java code to Python:
```
class ShutdownException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(str(cause), TSStatusCode.SHUT_DOWN_ERROR)
        elif message is not None:
            super().__init__(message, TSStatusCode.SHUT_DOWN_ERROR)
        else:
            raise ValueError("Either 'message' or 'cause' must be provided")

    @classmethod
    def from_error_code(cls, error_code: int) -> "ShutdownException":
        return cls(f"Error code {error_code}", None, error_code)

TSStatusCode = {
    TSStatusCode.SHUT_DOWN_ERROR: 1,
}
```
Note that I've used Python's built-in `Exception` class as the base class for our custom exception. In Java, you would typically use a specific exception hierarchy (e.g., `IOException`, `RuntimeException`) but in Python, it's common to just inherit from the general-purpose `Exception` class.

I also removed the redundant constructor that took only an error code and message, since we can simply pass those values directly to the parent class using the `super().__init__()` method.