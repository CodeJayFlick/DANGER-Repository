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
