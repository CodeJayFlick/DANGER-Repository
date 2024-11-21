Here is the translation of the Java code to Python:
```
class AccessPcodeExecutionException(Exception):
    def __init__(self, message: str = None, frame=None, cause: Exception = None) -> None:
        if cause is not None:
            super().__init__(message, cause)
        elif frame is not None and message is not None:
            super().__init__(f"{message} (frame={frame})")
        else:
            super().__init__(message)

    def __str__(self) -> str:
        return self.args[0]
```
Note that I've used Python's built-in `Exception` class as the base class for our custom exception, and implemented the same constructors as in the Java code. The `__str__` method is also added to provide a nice string representation of the exception.

Also, note that Python does not have an equivalent concept to Java's "package" declaration at the top of the file.