class WrapIDebugSymbols4:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__(pv_instance)

# Define a class that inherits from Structure and ByReference
from ctypes import POINTER, c_void_p

class IDebugSymbols4_ByReference(Structure.ByReference):
    _fields_ = []

class WrapIDebugSymbols4(IDebugSymbols4):
    def __init__(self):
        pass

    def __init__(self, pv_instance: POINTER(c_void_p)):
        super().__init__(pv_instance)
