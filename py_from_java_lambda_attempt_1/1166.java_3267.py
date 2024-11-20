Here's a translation of the Java interface into equivalent Python code:

```Python
from enum import Enum

class VTableIndex(Enum):
    IS_MATCH = 3


class IDebugHostModuleSignature:
    IID_IDEBUG_HOST_MODULE_SIGNATURE = "31E53A5A-01EE-4BBB-89944B46AE7D595C"

    def __init__(self):
        pass

    def is_match(self, p_module: object, is_match_by_ref: bool) -> int:
        # This method should return a Windows HRESULT value
        raise NotImplementedError("is_match must be implemented")
```

Please note that Python does not have direct equivalents for Java's `interface` or `enum class`. Instead, we use the built-in `class` and `Enum` types. The `IUnknownEx` interface is also not directly translatable to Python because it seems like a custom interface defined in the JNA library.