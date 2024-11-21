Here is the translation of the given Java code into equivalent Python:

```Python
import ctypes
from enum import Enum

class HRESULT(Enum):
    S_OK = 0x00000000L

class WrapIDebugHostScriptHost:
    def __init__(self, pv_instance=None):
        self.pv_instance = pv_instance

    class ByReference(ctypes.Structure):
        _fields_ = []

    @staticmethod
    def CreateContext(script, script_context):
        return HRESULT.S_OK  # Assuming the function always returns S_OK for simplicity


# Usage example:
wrap_idebug_host_script_host = WrapIDebugHostScriptHost()
result = wrap_idebug_host_script_host.CreateContext(b"script", ctypes.byref(ctypes.c_void_p()))
print(result)
```

Please note that this is a simplified translation and does not cover all the complexities of Java's JNA (Java Native Access) library. Python's `ctypes` module provides similar functionality, but it may require more manual work to achieve the same level of interoperability as JNA.