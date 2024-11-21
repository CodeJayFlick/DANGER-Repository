class WrapIDebugHostSymbolEnumerator:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        super().__init__()

    def Reset(self) -> int:
        return self._invoke_hr(0x1, None)

    def GetNext(self, symbol: 'ctypes.POINTER') -> int:
        return self._invoke_hr(0x2, None, symbol)

class ByReference(WrapIDebugHostSymbolEnumerator):
    pass

import ctypes
from enum import IntEnum

VTIndices = IntEnum('VTIndices', 
                     {'RESET': 1,
                      'GET_NEXT': 2})

def _invoke_hr(self, hr_index: int, pv_instance=None, symbol=None) -> int:
    # implement the logic for invoking HR here
    pass
