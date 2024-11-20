Here is the equivalent Python code:

```
class LongRunningEventException(Exception):
    def __init__(self, message: str):
        super().__init__(message)
```

Note that in Python, we don't need a `package` declaration or an explicit `extends Exception`. The `LongRunningEventException` class simply inherits from the built-in `Exception` class.