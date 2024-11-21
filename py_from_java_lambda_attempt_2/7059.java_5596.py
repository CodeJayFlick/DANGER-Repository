Here is the equivalent Python code:

```Python
class UnknownArtStorageModeException(Exception):
    def __init__(self, storage_mode: int) -> None:
        super().__init__(f"Unrecognized storage mode: 0x{storage_mode:x}")
```

Note that in Python, we don't need to specify a package name or import specific modules. The `UnknownArtStorageModeException` class is defined as a subclass of the built-in `Exception` class, and it overrides the constructor (`__init__`) method to set its message based on the provided storage mode value.