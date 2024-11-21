import ctypes
from comtypes import HRESULT

class DebugHostSymbolEnumeratorImpl:
    def __init__(self, jna_data):
        self.cleanable = None  # No direct equivalent in Python
        self.jna_data = jna_data

    def get_pointer(self):
        return self.jna_data.get_pointer()

    def reset(self):
        hr = self.jna_data.reset()
        if not HRESULT(hr).succeeded:
            raise Exception(f"Reset failed with error code {hr}")

    def next(self):
        pp_symbol = ctypes.POINTER(ctypes.c_void_p)()  # No direct equivalent in Python
        hr = self.jna_data.get_next(pp_symbol)
        if not HRESULT(hr).succeeded:
            return None

        wrap = WrapIDebugHostSymbol1(pp_symbol.value)
        try:
            result = DebugHostSymbolInternal.try_preferred_interfaces(wrap.query_interface)
            return result
        finally:
            wrap.release()
