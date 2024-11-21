from enum import Enum
import ctypes

class VTableIDebugOutputCallbacks2:
    class ByReference(ctypes.Structure):
        pass

    FIELDS = ["QueryInterfaceCallback", "AddRefCallback", "ReleaseCallback",
              "OutputCallback", "GetInterestMaskCallback", "Output2Callback"]

    def __init__(self):
        self.GetInterestMaskCallback = None
        self.Output2Callback = None

    @property
    def field_order(self):
        return VTableIDebugOutputCallbacks2.FIELDS


class GetInterestMaskCallback(ctypes.CFUNCTYPE(ctypes.c_ulonglong, ctypes.POINTER(None), ctypes.POINTER(ctypes.c_ulong))):
    pass


class Output2Callback(ctypes.CFUNCTYPE(ctypes.c_longlong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulonglong, ctypes.wstring)):
    pass
