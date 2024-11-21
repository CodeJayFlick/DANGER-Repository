Here is the translation of the given Java code into equivalent Python:

```Python
class OverlappingFunctionException(Exception):
    def __init__(self, entry_point=None, overlapping_range=None, message=""):
        if not message:
            if entry_point and overlapping_range:
                message = f"Unable to create function at {entry_point} due to overlap with range [{overlapping_range[0]}, {overlapping_range[1]}]"
            elif entry_point:
                message = f"Unable to create function at {entry_point} due to overlap with another namespace"
        super().__init__(message)
```

Note that Python does not have a direct equivalent of Java's `package` declaration. The class itself is defined as `OverlappingFunctionException`, and it inherits from the built-in `Exception`.