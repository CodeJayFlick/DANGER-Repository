Here is the translation of the given Java interface into a Python class:

```Python
from enum import Enum

class VTIndices(Enum):
    RESET = 0
    GET_NEXT = 1


class IDataModelScriptDebugBreakpointEnumerator:
    IID_IData_Model_Script_Debug_Breakpoint_Enum = "39484A75-4F3B479986DA691AF57B299"

    def __init__(self):
        pass

    def Reset(self) -> int:
        # Implement the logic for resetting
        return 0

    def GetNext(self, breakpoint: 'PointerByReference') -> int:
        # Implement the logic for getting next breakpoint
        return 0


class PointerByReference:
    def __init__(self):
        pass
```

Please note that Python does not have direct equivalent of Java's `interface` keyword. Instead, we use a class to define an interface in Python. Also, there is no direct equivalent of Java's `enum` keyword for defining enumerations in Python. We can achieve this using the built-in `Enum` class from the enum module.

In the above code:

- The `VTIndices` class represents the enumeration.
- The `IDataModelScriptDebugBreakpointEnumerator` class represents the interface and its methods.
- The `PointerByReference` class is used to represent a reference to a pointer.