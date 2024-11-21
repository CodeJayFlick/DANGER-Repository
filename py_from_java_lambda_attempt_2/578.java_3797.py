Here is the translation of the given Java code into equivalent Python:

```Python
from uuid import UUID

class VTIndices5:
    GET_CURRENT_SCOPE_FRAME_INDEX_EX = 0
    SET_SCOPE_FRAME_BY_INDEX_EX = 1


class IDebugSymbols5(IDebugSymbols4):
    IID_IDEBUG_SYMBOLS5 = UUID("c65fa83e-1e69-475e-8e0e-9cc17eb5d79")

```

Note: Python does not have direct equivalent of Java's `enum` and `interface`. In the above code, I used a class (`VTIndices5`) to define an enumeration-like structure. Similarly, I used inheritance from another abstract base class (`IDebugSymbols4`) to mimic the concept of interface in Java.

Also note that Python does not have direct equivalent of Java's `IID` and `VTableIndex`. In the above code, I used Python's built-in `UUID` module to define a unique identifier.