Here is the translation of the Java code to Python:
```
class ServiceConstructionException(Exception):
    def __init__(self, message: str, cause: Exception) -> None:
        super().__init__(message, cause)

    def unwrap(self, cls: type[Exception]) -> None:
        cause = self.__cause__
        if isinstance(cause, cls):
            raise cls(cause)
```
Note that I've used Python's built-in `Exception` class as the base class for our custom exception. In Java, you would use `extends Exception`, but in Python, we don't need to specify this explicitly.

Also, note that I've replaced the Java-style constructor with a regular Python method (`__init__`). The `super().__init__(message, cause)` call is equivalent to calling the parent class's constructor with the given arguments.