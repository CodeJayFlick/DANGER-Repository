Here's the equivalent Python code:

```Python
class PEfException(Exception):
    """An exception class to handle encountering invalid PEF Headers."""

    def __init__(self, message: str) -> None:
        super().__init__(message)

    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
```

Note that Python does not have a direct equivalent of Java's `package` statement. The class is defined directly in the script without any package declaration.

Also note that Python 3.x has type hints for variables and function parameters (e.g., `str`, `Exception`) which are used to indicate what types of data should be passed as arguments or returned from functions, but these do not affect how the code runs.