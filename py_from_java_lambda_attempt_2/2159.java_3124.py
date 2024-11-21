Here is the translation of the given Java code into equivalent Python:

```Python
class DebuggerUserException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
```

Note that in Python, we don't need to specify a package name or use `public` and `extends`. The base class for exceptions is simply `Exception`, so we can inherit from it directly.