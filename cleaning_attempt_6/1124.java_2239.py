import ctypes

class WrapIDataModelScriptDebug2:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__(pv_instance)

    def set_breakpoint_at_function(self, function_name: str, breakpoint: 'ctypes.POINTER') -> int:
        return self._invoke_hr(0x02, bytes(function_name.encode()), ctypes.byref(breakpoint))

class ByReference(WrapIDataModelScriptDebug2):
    pass

def _invoke_hr(index: int, pv_instance: bytes, function_name: str, breakpoint: 'ctypes.POINTER') -> int:
    # implement this method to call the underlying API
    return 0x01  # placeholder for HRESULT value
