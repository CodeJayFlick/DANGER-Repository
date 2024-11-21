Here is the translation of the given Java code into equivalent Python:

```Python
import ctypes
from enum import Enum

class BasicType(Enum):
    VOID = 0
    CHAR = 1
    SHORT = 2
    INT = 3
    LONG = 4
    FLOAT = 5
    DOUBLE = 6
    POINTER = 7
    ENUM = 8
    FUNCTION = 9

class TemplateArgumentKind(Enum):
    TYPE = 0
    VALUE = 1

class SBType:
    def __init__(self, c_ptr=0, own_memory=False):
        self._c_ptr = c_ptr
        self._own_memory = own_memory

    @property
    def _c_ptr(self):
        return self._c_ptr

    @_c_ptr.setter
    def _c_ptr(self, value):
        if not isinstance(value, int) or value < 0:
            raise ValueError("Invalid C pointer")
        self._c_ptr = value

    @property
    def _own_memory(self):
        return self._own_memory

    @_own_memory.setter
    def _own_memory(self, value):
        if not isinstance(value, bool):
            raise ValueError("Own memory must be a boolean")
        self._own_memory = value

    def __del__(self):
        if self._c_ptr:
            lldbJNI.delete_SBType(self._c_ptr)
            self._c_ptr = 0
            self._own_memory = False

    @property
    def IsValid(self):
        return bool(lldbJNI.SBType_IsValid(self._c_ptr))

    @property
    def GetByteSize(self):
        return lldbJNI.SBType_GetByteSize(self._c_ptr)

    @property
    def IsPointerType(self):
        return bool(lldbJNI.SBType_IsPointerType(self._c_ptr))

    # ... and so on for all the methods

lldbJNI = ctypes.CDLL("path_to_your_lldbjni_library")
```

Please note that you will need to replace `"path_to_your_lldbjni_library"` with the actual path to your `lldbjni` library.