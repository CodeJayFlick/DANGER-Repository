import ctypes
from comtypes import *

class WrapIDataModelManager1:
    def __init__(self):
        pass

    def Close(self):
        return self._invokeHR(0x00010001, None)

    def CreateNoValue(self, object_byref=None):
        if object_byref is not None:
            ctypes.byref(object_byref)
        return self._invokeHR(0x00020002, None, object_byref)

    def CreateErrorObject(self, hr_error, pwsz_message, object_byref=None):
        if object_byref is not None:
            ctypes.byref(object_byref)
        return self._invokeHR(0x00030003, None, hr_error, pwsz_message, object_byref)

    # ... and so on for the rest of the methods

class ByReference(WrapIDataModelManager1):
    pass
