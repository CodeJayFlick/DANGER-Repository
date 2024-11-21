Here is the translation of the given Java code into Python:

```Python
class DebuggerModelTerminatingException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        else:
            super().__init__(message)

if __name__ == "__main__":
    pass
```

Note that Python does not have a direct equivalent to Java's `package` statement. In Python, you can use modules or packages as needed. The given code is translated into a class named `DebuggerModelTerminatingException`, which inherits from the built-in `Exception`.