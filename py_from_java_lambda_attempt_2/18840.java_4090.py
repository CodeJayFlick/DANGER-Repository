Here is the translation of the given Java code into equivalent Python:

```Python
class NessieConflictException(Exception):
    def __init__(self, message: str = None, cause: Exception = None) -> None:
        if not message:
            super().__init__("Conflict")
        else:
            super().__init__(message)
        
        self.status_code = 409

    @classmethod
    def from_error(cls, error):
        return cls(error.to_string())
```

Note that Python does not have a direct equivalent to Java's `package` declaration. The code above is written in the context of a typical Python program and can be used as-is.

Also note that Python uses indentation (spaces or tabs) for block-level structure instead of curly braces like Java, so I've removed those from the translation.