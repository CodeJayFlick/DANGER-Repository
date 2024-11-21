Here is the translation of the given Java code into equivalent Python code:

```Python
import ctypes
from enum import Enum

class ByteOrder(Enum):
    LITTLE_ENDIAN = 0
    BIG_ENDIAN = 1

class StateType(Enum):
    UNKNOWN = -1
    STOPPED = 0
    RUNNING = 1
    DEAD = 2

class SBProcess:
    def __init__(self, c_ptr=None, own_memory=False):
        self._c_ptr = ctypes.c_longlong(c_ptr)
        self._own_memory = bool(own_memory)

    @property
    def _swig_cptr(self):
        return self._c_ptr.value if self._c_ptr else 0

    def __del__(self):
        self.delete()

    def delete(self):
        if not self._c_ptr:
            return
        lldbJNI.SBProcess_delete(self._swig_cptr)
        self._own_memory = False
        self._c_ptr.value = 0

    @staticmethod
    def GetBroadcasterClassName():
        return lldbJNI.SBProcess_GetBroadcasterClassName()

    def GetPluginName(self):
        return lldbJNI.SBProcess_GetPluginName(self._swig_cptr, self)

    def GetShortPluginName(self):
        return lldbJNI.SBProcess_GetShortPluginName(self._swig_cptr, self)

    # ... and so on for all the methods

lldbJNI = ctypes.CDLL('path_to_your_lldb_library')  # replace with your actual library path
```

Note that you will need to have a Python wrapper around the C++ `lldb` library. The above code assumes that this is already done, and provides an example of how to translate Java-like code into equivalent Python code.

The translation involves:

1. Replacing Java's `public class SBProcess { ... }` with Python's `class SBProcess:`.
2. Converting Java's `private transient long swigCPtr;` and similar fields into Python properties (`@property`) that return the underlying C pointer value.
3. Translating Java's method calls (e.g., `lldbJNI.SBProcess_GetBroadcasterClassName()`) into equivalent Python code using the `ctypes.CDLL` module to access the C++ library functions.

The actual translation may vary depending on specific requirements and constraints of your project.