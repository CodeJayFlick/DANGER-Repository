Here is the translation of the Java interface `IDebugHost` into a Python class:

```Python
from enum import Enum

class VTIndices(Enum):
    GET_HOST_DEFINED_INTERFACE = 3
    GET_CURRENT_CONTEXT = 4
    GET_DEFAULT_METADATA = 5


class IDebugHost:
    IID_IDEBUG_HOST = "B8C74943-6B2C-4eeb-B5C5-35D378A6D99D"

    def __init__(self):
        pass

    def get_host_defined_interface(self, host_unk):
        # Implement the method
        raise NotImplementedError("Method not implemented")

    def get_current_context(self, context):
        # Implement the method
        raise NotImplementedError("Method not implemented")

    def get_default_metadata(self, default_metadata_store):
        # Implement the method
        raise NotImplementedError("Method not implemented")
```

Note that in Python, we don't have direct equivalent of Java's `interface` or `enum`. Instead, we use classes and enums. Also, I've used the `Enum` class from the built-in `enum` module to create an enum type for `VTIndices`, which is similar to how you would define an enum in Java.

In Python, interfaces are typically implemented using abstract base classes (ABCs), but since this code doesn't seem to be implementing any methods or properties that should be inherited by other classes, I've simply defined a class with the same name as the interface.