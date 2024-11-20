Here's a translation of the Java interface into equivalent Python:

```Python
from enum import Enum

class VTIndices(Enum):
    GET_HASH_CODE = 3
    IS_MATCH = 4
    COMPARE_AGAINST = 5


class IDebugHostTypeSignature:
    IID_IDEBUG_HOST_TYPE_SIGNATURE = "3AADC353-2B14-4abb-9893-5E03458E07EE"

    def __init__(self):
        pass

    def GetHashCode(self, hashCode):
        # Implement the HRESULT return type
        raise NotImplementedError("GetHashCode is not implemented")

    def IsMatch(self, type, is_match, wildcard_matches):
        # Implement the HRESULT return type
        raise NotImplementedError("IsMatch is not implemented")

    def CompareAgainst(self, type_signature, result):
        # Implement the HRESULT return type
        raise NotImplementedError("CompareAgainst is not implemented")
```

Note that this translation does not include any JNA (Java Native Access) functionality. Python has its own way of interacting with native code using libraries like ctypes or cffi.