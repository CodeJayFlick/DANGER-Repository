Here is the translation of the given Java code into equivalent Python:

```Python
from enum import Enum

class VTIndicesX(Enum):
    GET_LOCATION_KIND = 0
    GET_LOCATION = 1


class IDebugHostPublic:
    IID_IDEBUG_HOST_PUBLIC = "6C597AC9-FB4D-4f6d-9F39-22488539F8F4"

    def get_location_kind(self):
        pass

    def get_location(self, location):
        pass
```

Note that Python does not have direct equivalent of Java's `interface` or `enum class`. In the above code:

1. The `VTIndicesX` is a simple enum in Python.
2. The `IDebugHostPublic` is an abstract base class (ABC) which represents the interface-like behavior.

The `get_location_kind` and `get_location` methods are placeholders for actual implementation, as they were declared to return `HRESULT`.