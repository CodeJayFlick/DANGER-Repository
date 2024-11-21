Here is the translation of the Java code to Python:
```
class NessieNotFoundException(Exception):
    """Base class for all exceptions that are represented by the HTTP 404 status code (Not Found)."""

    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if message is not None and cause is not None:
            super().__init__(message, 404, "Not Found", cause)
        elif message is not None:
            super().__init__(message, 404, "Not Found")
        else:
            raise ValueError("At least one of `message` or `cause` must be provided")

    def __init__(self, error: 'NessieError') -> None:
        super().__init__(error)
```
Note that I used the built-in Python exception class (`Exception`) as a base class for our custom exception. The constructor takes two optional arguments: `message` and `cause`. If both are provided, it calls the parent's constructor with all three arguments (message, status code 404, "Not Found", and cause). If only one is provided, it uses that to construct the exception.