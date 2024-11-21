Here is the translation of the Java code to Python:
```
class YggdrasilException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)

    def __init__(self, message: str, cause: Exception) -> None:
        super().__init__(f"{message}: {cause}")

    def __init__(self, cause: Exception) -> None:
        if cause is not None:
            super().__init__(f"{type(cause).__name__}{'' if cause.message is None else f": {cause.message}"}, cause)
```
Note that I've used Python's built-in `Exception` class as the base class for our custom exception, and also taken advantage of type hints to specify the types of the method parameters.