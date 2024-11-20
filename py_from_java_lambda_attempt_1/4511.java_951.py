Here is the equivalent Python code:

```
class ImproperUseException(Exception):
    """Exception class to be used when API calls are improperly used (i.e., GhidraScript.askProjectFolder() method is being used in Headless mode)."""

    def __init__(self, msg: str) -> None:
        super().__init__(msg)

    def __init__(self, cause: Exception) -> None:
        super().__init__(cause)
```

Note that Python does not have a direct equivalent to Java's `extends` keyword. Instead, we define the class as a subclass of the built-in `Exception` class using inheritance.

Also, in Python 3.x, it is recommended to use type hints for function parameters and return types, which I've included here.