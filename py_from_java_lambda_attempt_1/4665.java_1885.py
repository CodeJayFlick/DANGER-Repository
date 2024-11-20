Here is the translation of the given Java code into equivalent Python:

```Python
class DWARFPreconditionException(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
```

Note that in Python, we don't need to explicitly define a `package` or use the `public` keyword. The class is defined as a subclass of the built-in `Exception` class using inheritance (`DWARFPreconditionException(Exception)`).