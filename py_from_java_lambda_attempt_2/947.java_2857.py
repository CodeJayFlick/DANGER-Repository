Here is the translation of the given Java code into equivalent Python:

```Python
class DbgModelRuntimeError(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, message):
        super().__init__(message)
```

Note that in Python, we don't need to specify a package name or use the `public` keyword. Also, Python's exception handling is more straightforward than Java's - you can inherit from the built-in `Exception` class and override its constructor if needed.