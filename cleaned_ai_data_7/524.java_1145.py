import ctypes.util

class WrapIDebugControl5(ctypes.Structure):
    _fields_ = []

    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__(pv_instance)

ByReference = ctypes.POINTER(WrapIDebugControl5)
