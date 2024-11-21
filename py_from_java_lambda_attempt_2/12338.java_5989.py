Here is the equivalent Python code:

```Python
class InvalidDataTypeException(Exception):
    def __init__(self, message="Invalid data type error.", dt=None):
        if dt:
            super().__init__(f"Invalid data type error for {dt.get_display_name()}.")
        else:
            super().__init__(message)

    @classmethod
    def from_message(cls, message: str) -> 'InvalidDataTypeException':
        return cls(message)
```

Note that Python does not have a direct equivalent to Java's `extends` keyword. Instead, we define the class as a subclass of Python's built-in `Exception`. The constructors (`__init__`) are defined similarly to their Java counterparts.