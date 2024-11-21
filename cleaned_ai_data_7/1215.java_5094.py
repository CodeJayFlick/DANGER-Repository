import ctypes
from comtypes import HRESULT, BSTR, POINTER

class WrapIKeyEnumerator:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def Reset(self) -> HRESULT:
        return _invoke_hr(VTIndices.RESET, ctypes.c_void_p.in_dll(ctypes.windll.user32, 'pvInstance'))

    def GetNext(self, key: BSTR, value: POINTER, metadata: POINTER) -> HRESULT:
        return _invoke_hr(VTIndices.GET_NEXT, self.pv_instance, key, value, metadata)

class ByReference(WrapIKeyEnumerator):
    pass

def _invoke_hr(operation: int, pv_instance: ctypes.c_void_p, *args) -> HRESULT:
    # This function should be implemented based on the actual functionality
    return 0x80070057  # Assuming an error code for now

VTIndices = {
    'RESET': 1,
    'GET_NEXT': 2
}
