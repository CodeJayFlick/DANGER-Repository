Here is the equivalent Python code:

```Python
class AssemblySyntaxException(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = set(errors) if errors else None

    @classmethod
    def from_errors(cls, errors):
        return cls("\n".join(str(error) for error in errors), errors)

    def get_errors(self):
        return frozenset(self.errors) if self.errors is not None else None
```

Note that Python does not have a direct equivalent to Java's `Set` and `Collection`. Instead, we use the built-in set data type. The `get_errors()` method returns an unmodifiable frozen set of errors for consistency with the original code.