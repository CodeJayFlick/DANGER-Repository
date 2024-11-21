import ctypes.util

class WrapIUnknownEx:
    def __init__(self):
        pass

    def __init__(self, pv_instance: bytes):
        super().__init__(pv_instance)

class ByReference(Structure):
    _fields_ = []

WrapIUnknownEx.ByReference = ByReference
