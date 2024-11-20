Here is the translation of the given Java code into equivalent Python:

```Python
class AssemblyError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
```

Note that in Python, we don't need to specify a package name or use `public` access modifiers. The class is defined directly within the script and inherits from the built-in `Exception` class.